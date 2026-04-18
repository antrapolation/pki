# Mnesia Backup Restore Procedure

## Prerequisites
- `age` CLI installed (for decryption)
- Access to the tenant's Mnesia directory
- Tenant node stopped

## Restore from Local Backup

1. Stop the tenant node
2. List available backups:
   ```bash
   ls -la /var/lib/pki/tenants/<slug>/backups/
   ```
3. Restore:
   ```bash
   # In tenant IEx (or via eval):
   :mnesia.restore('/var/lib/pki/tenants/<slug>/backups/mnesia-<timestamp>.bak',
     [{:default_op, :recreate_tables}])
   ```

## Restore from S3 Backup

1. Download the backup:
   ```bash
   aws s3 cp s3://<bucket>/tenant-<slug>/mnesia-<timestamp>.bak.age .
   ```
2. Decrypt:
   ```bash
   age -d -i /etc/pki/age.key mnesia-<timestamp>.bak.age > mnesia.bak
   ```
3. Stop the tenant node
4. Restore:
   ```elixir
   :mnesia.restore('mnesia.bak', [{:default_op, :recreate_tables}])
   ```
5. Restart the tenant node

## Verify After Restore
- Check tenant health: `curl <slug>.ca.<domain>/health`
- Verify key count matches expectations
- Test a signing operation
