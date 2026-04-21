use cryptoki::context::Pkcs11;
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, ObjectClass};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use rustler::{Atom, Error, NifResult};
use secrecy::Secret;
use std::convert::TryFrom;
use std::path::Path;

mod atoms {
    rustler::atoms! {
        ok,
        error,
        not_implemented,
        invalid_algo,
        pkcs11_error,
    }
}

fn open_session(pkcs11: &Pkcs11, slot_id: u64, pin: &str) -> std::result::Result<Session, String> {
    let slot = Slot::try_from(slot_id).map_err(|e| format!("Invalid slot: {}", e))?;
    let session = pkcs11
        .open_rw_session(slot)
        .map_err(|e| format!("Failed to open session: {}", e))?;

    session
        .login(UserType::User, Some(&Secret::new(pin.to_string())))
        .map_err(|e| format!("Failed to login: {}", e))?;

    Ok(session)
}

#[rustler::nif]
fn get_info(lib_path: String) -> NifResult<(Atom, String)> {
    let pkcs11 = Pkcs11::new(Path::new(&lib_path))
        .map_err(|e| Error::Term(Box::new(format!("Failed to load library: {}", e))))?;

    pkcs11
        .initialize(cryptoki::context::CInitializeArgs::OsThreads)
        .or_else(|e| {
            if format!("{}", e).contains("CRYPTOKI_ALREADY_INITIALIZED") {
                Ok(())
            } else {
                Err(e)
            }
        })
        .map_err(|e| Error::Term(Box::new(format!("Failed to initialize: {}", e))))?;

    let info = pkcs11
        .get_library_info()
        .map_err(|e| Error::Term(Box::new(format!("Failed to get info: {}", e))))?;

    Ok((atoms::ok(), info.manufacturer_id().to_string()))
}

#[rustler::nif]
fn list_slots(lib_path: String) -> NifResult<(Atom, Vec<u64>)> {
    let pkcs11 = Pkcs11::new(Path::new(&lib_path))
        .map_err(|e| Error::Term(Box::new(format!("Failed to load library: {}", e))))?;

    pkcs11
        .initialize(cryptoki::context::CInitializeArgs::OsThreads)
        .or_else(|e| {
            if format!("{}", e).contains("CRYPTOKI_ALREADY_INITIALIZED") {
                Ok(())
            } else {
                Err(e)
            }
        })
        .map_err(|e| Error::Term(Box::new(format!("Failed to initialize: {}", e))))?;

    let slots = pkcs11
        .get_slots_with_token()
        .map_err(|e| Error::Term(Box::new(format!("Failed to get slots: {}", e))))?;

    let ids: Vec<u64> = slots.into_iter().map(|s| s.id()).collect();
    Ok((atoms::ok(), ids))
}

#[rustler::nif]
fn generate_key<'a>(env: rustler::Env<'a>, lib_path: String, slot_id: u64, pin: String, algo: String, bits: u32) -> NifResult<(Atom, String, rustler::Binary<'a>)> {
    let pkcs11 = Pkcs11::new(Path::new(&lib_path))
        .map_err(|e| Error::Term(Box::new(format!("Failed to load library: {}", e))))?;

    pkcs11
        .initialize(cryptoki::context::CInitializeArgs::OsThreads)
        .ok();

    let session = open_session(&pkcs11, slot_id, &pin)
        .map_err(|e| Error::Term(Box::new(e)))?;

    let id = format!("key_{}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0));
    
    let (mechanism, pub_attr, priv_attr) = match algo.as_str() {
        "rsa" => {
            let pub_attr = vec![
                Attribute::Token(true),
                Attribute::Verify(true),
                Attribute::Encrypt(true),
                Attribute::ModulusBits((bits as u64).into()),
                Attribute::PublicExponent(vec![0x01, 0x00, 0x01]),
                Attribute::Label(id.clone().into_bytes()),
                Attribute::Id(id.clone().into_bytes()),
            ];
            let priv_attr = vec![
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Sign(true),
                Attribute::Decrypt(true),
                Attribute::Label(id.clone().into_bytes()),
                Attribute::Id(id.clone().into_bytes()),
            ];
            (Mechanism::RsaPkcsKeyPairGen, pub_attr, priv_attr)
        }
        "ecc" => {
            // secp256r1 OID: 1.2.840.10045.3.1.7 (DER: 06 08 2a 86 48 ce 3d 03 01 07)
            let ec_params = vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
            let pub_attr = vec![
                Attribute::Token(true),
                Attribute::Verify(true),
                Attribute::EcParams(ec_params),
                Attribute::Label(id.clone().into_bytes()),
                Attribute::Id(id.clone().into_bytes()),
            ];
            let priv_attr = vec![
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Sign(true),
                Attribute::Label(id.clone().into_bytes()),
                Attribute::Id(id.clone().into_bytes()),
            ];
            (Mechanism::EccKeyPairGen, pub_attr, priv_attr)
        }
        _ => return Err(Error::Term(Box::new("Unsupported algorithm"))),
    };

    let keypair = session
        .generate_key_pair(&mechanism, &pub_attr, &priv_attr)
        .map_err(|e| Error::Term(Box::new(format!("Failed to generate keypair: {}", e))))?;

    // Fetch public key material
    // For RSA, we need Modulus and PublicExponent to build something useful in Elixir, 
    // or just return the handle-based material if we can.
    // However, returning raw material is better.
    // For ECC, we need EcPoint.
    
    let mut material = Vec::new();

    match algo.as_str() {
        "rsa" => {
            let attrs = session.get_attributes(keypair.0, &[
                cryptoki::object::AttributeType::Modulus,
                cryptoki::object::AttributeType::PublicExponent,
            ]).map_err(|e| Error::Term(Box::new(format!("Failed to get RSA attributes: {}", e))))?;
            
            // We'll just return the Modulus for now as "material" or a simple concat if needed.
            // Better to return it in a way Elixir can parse.
            // For now, let's just return the modulus.
            if let Attribute::Modulus(m) = &attrs[0] {
                material.extend_from_slice(m);
            }
        },
        "ecc" => {
            let attrs = session.get_attributes(keypair.0, &[
                cryptoki::object::AttributeType::EcPoint,
            ]).map_err(|e| Error::Term(Box::new(format!("Failed to get ECC attributes: {}", e))))?;
            
            if let Attribute::EcPoint(p) = &attrs[0] {
                material.extend_from_slice(p);
            }
        },
        _ => {}
    }

    let mut binary = rustler::OwnedBinary::new(material.len()).unwrap();
    binary.as_mut_slice().copy_from_slice(&material);

    Ok((atoms::ok(), id, binary.release(env)))
}

#[rustler::nif]
fn sign<'a>(env: rustler::Env<'a>, lib_path: String, slot_id: u64, pin: String, key_id: String, algo: String, data: rustler::Binary<'a>) -> NifResult<(Atom, rustler::Binary<'a>)> {
    let pkcs11 = Pkcs11::new(Path::new(&lib_path))
        .map_err(|e| Error::Term(Box::new(format!("Failed to load library: {}", e))))?;

    pkcs11.initialize(cryptoki::context::CInitializeArgs::OsThreads).ok();

    let session = open_session(&pkcs11, slot_id, &pin)
        .map_err(|e| Error::Term(Box::new(e)))?;

    // Find the private key with the given ID
    let search_template = vec![
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::Id(key_id.into_bytes()),
    ];
    
    let objects = session
        .find_objects(&search_template)
        .map_err(|e| Error::Term(Box::new(format!("Failed to find key: {}", e))))?;
    
    let key_handle = objects.get(0).ok_or_else(|| Error::Term(Box::new("Key not found")))?;

    let mechanism = match algo.as_str() {
        "rsa" => Mechanism::RsaPkcs,
        "ecc" => Mechanism::Ecdsa,
        _ => return Ok((atoms::not_implemented(), rustler::OwnedBinary::new(0).unwrap().release(env))),
    };

    let signature_vec = session
        .sign(&mechanism, *key_handle, data.as_slice())
        .map_err(|e| Error::Term(Box::new(format!("Failed to sign: {}", e))))?;

    let mut binary = rustler::OwnedBinary::new(signature_vec.len()).unwrap();
    binary.as_mut_slice().copy_from_slice(&signature_vec);

    Ok((atoms::ok(), binary.release(env)))
}

#[rustler::nif]
fn verify<'a>(_lib_path: String, slot_id: u64, pin: String, key_id: String, algo: String, data: rustler::Binary<'a>, signature: rustler::Binary<'a>) -> NifResult<Atom> {
    let pkcs11 = Pkcs11::new(Path::new(&_lib_path))
        .map_err(|e| Error::Term(Box::new(format!("Failed to load library: {}", e))))?;

    pkcs11.initialize(cryptoki::context::CInitializeArgs::OsThreads).ok();

    let session = open_session(&pkcs11, slot_id, &pin)
        .map_err(|e| Error::Term(Box::new(e)))?;

    // Find the public key with the given ID
    let search_template = vec![
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::Id(key_id.into_bytes()),
    ];
    
    let objects = session
        .find_objects(&search_template)
        .map_err(|e| Error::Term(Box::new(format!("Failed to find key: {}", e))))?;
    
    let key_handle = objects.get(0).ok_or_else(|| Error::Term(Box::new("Key not found")))?;

    let mechanism = match algo.as_str() {
        "rsa" => Mechanism::RsaPkcs,
        "ecc" => Mechanism::Ecdsa,
        _ => return Ok(atoms::not_implemented()),
    };

    session
        .verify(&mechanism, *key_handle, data.as_slice(), signature.as_slice())
        .map_err(|e| Error::Term(Box::new(format!("Failed to verify: {}", e))))?;

    Ok(atoms::ok())
}

#[rustler::nif]
fn encrypt<'a>(env: rustler::Env<'a>, lib_path: String, slot_id: u64, pin: String, key_id: String, algo: String, data: rustler::Binary<'a>) -> NifResult<(Atom, rustler::Binary<'a>)> {
    let pkcs11 = Pkcs11::new(Path::new(&lib_path))
        .map_err(|e| Error::Term(Box::new(format!("Failed to load library: {}", e))))?;

    pkcs11.initialize(cryptoki::context::CInitializeArgs::OsThreads).ok();

    let session = open_session(&pkcs11, slot_id, &pin)
        .map_err(|e| Error::Term(Box::new(e)))?;

    // Find the public key with the given ID
    let search_template = vec![
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::Id(key_id.into_bytes()),
    ];
    
    let objects = session
        .find_objects(&search_template)
        .map_err(|e| Error::Term(Box::new(format!("Failed to find key: {}", e))))?;
    
    let key_handle = objects.get(0).ok_or_else(|| Error::Term(Box::new("Key not found")))?;

    let mechanism = match algo.as_str() {
        "rsa" => Mechanism::RsaPkcs,
        _ => return Ok((atoms::not_implemented(), rustler::OwnedBinary::new(0).unwrap().release(env))),
    };

    let encrypted_vec = session
        .encrypt(&mechanism, *key_handle, data.as_slice())
        .map_err(|e| Error::Term(Box::new(format!("Failed to encrypt: {}", e))))?;

    let mut binary = rustler::OwnedBinary::new(encrypted_vec.len()).unwrap();
    binary.as_mut_slice().copy_from_slice(&encrypted_vec);

    Ok((atoms::ok(), binary.release(env)))
}

#[rustler::nif]
fn decrypt<'a>(env: rustler::Env<'a>, lib_path: String, slot_id: u64, pin: String, key_id: String, algo: String, data: rustler::Binary<'a>) -> NifResult<(Atom, rustler::Binary<'a>)> {
    let pkcs11 = Pkcs11::new(Path::new(&lib_path))
        .map_err(|e| Error::Term(Box::new(format!("Failed to load library: {}", e))))?;

    pkcs11.initialize(cryptoki::context::CInitializeArgs::OsThreads).ok();

    let session = open_session(&pkcs11, slot_id, &pin)
        .map_err(|e| Error::Term(Box::new(e)))?;

    // Find the private key with the given ID
    let search_template = vec![
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::Id(key_id.into_bytes()),
    ];
    
    let objects = session
        .find_objects(&search_template)
        .map_err(|e| Error::Term(Box::new(format!("Failed to find key: {}", e))))?;
    
    let key_handle = objects.get(0).ok_or_else(|| Error::Term(Box::new("Key not found")))?;

    let mechanism = match algo.as_str() {
        "rsa" => Mechanism::RsaPkcs,
        _ => return Ok((atoms::not_implemented(), rustler::OwnedBinary::new(0).unwrap().release(env))),
    };

    let decrypted_vec = session
        .decrypt(&mechanism, *key_handle, data.as_slice())
        .map_err(|e| Error::Term(Box::new(format!("Failed to decrypt: {}", e))))?;

    let mut binary = rustler::OwnedBinary::new(decrypted_vec.len()).unwrap();
    binary.as_mut_slice().copy_from_slice(&decrypted_vec);

    Ok((atoms::ok(), binary.release(env)))
}

#[rustler::nif]
fn set_pin(lib_path: String, slot_id: u64, old_pin: String, new_pin: String) -> NifResult<Atom> {
    let pkcs11 = Pkcs11::new(Path::new(&lib_path))
        .map_err(|e| Error::Term(Box::new(format!("Failed to load library: {}", e))))?;

    pkcs11.initialize(cryptoki::context::CInitializeArgs::OsThreads).ok();

    let session = open_session(&pkcs11, slot_id, &old_pin)
        .map_err(|e| Error::Term(Box::new(e)))?;

    session
        .set_pin(&Secret::new(old_pin), &Secret::new(new_pin))
        .map_err(|e| Error::Term(Box::new(format!("Failed to set PIN: {}", e))))?;

    Ok(atoms::ok())
}

rustler::init!("Elixir.StrapSofthsmPrivKeyStoreProvider.Native.SofthsmNif");
