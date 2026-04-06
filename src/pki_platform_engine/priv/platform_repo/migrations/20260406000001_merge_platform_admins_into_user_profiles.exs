defmodule PkiPlatformEngine.PlatformRepo.Migrations.MergePlatformAdminsIntoUserProfiles do
  use Ecto.Migration

  def up do
    # Step 1: Add global_role column to user_profiles
    alter table(:user_profiles) do
      add_if_not_exists :global_role, :string
    end

    # Step 2: Migrate platform_admins into user_profiles
    # For each platform_admin:
    #   - If username already exists in user_profiles → update global_role to "super_admin"
    #   - If username doesn't exist → insert into user_profiles
    execute """
    INSERT INTO user_profiles (id, username, password_hash, display_name, email, status,
                               must_change_password, credential_expires_at, global_role,
                               inserted_at, updated_at)
    SELECT pa.id, pa.username, pa.password_hash, pa.display_name, pa.email, pa.status,
           pa.must_change_password, pa.credential_expires_at, 'super_admin',
           pa.inserted_at, pa.updated_at
    FROM platform_admins pa
    WHERE NOT EXISTS (
      SELECT 1 FROM user_profiles up WHERE up.username = pa.username
    )
    """

    # For users that already exist in both tables, just set the global_role
    execute """
    UPDATE user_profiles
    SET global_role = 'super_admin'
    FROM platform_admins pa
    WHERE user_profiles.username = pa.username
      AND user_profiles.global_role IS NULL
    """
  end

  def down do
    alter table(:user_profiles) do
      remove_if_exists :global_role, :string
    end
  end
end
