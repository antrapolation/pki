defmodule PkiPlatformEngine.EmailTemplates do
  def verification_code(code) do
    """
    <!DOCTYPE html>
    <html>
    <head><meta charset="utf-8"></head>
    <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 560px; margin: 0 auto; padding: 40px 20px; color: #1a1a2e;">
      <div style="text-align: center; margin-bottom: 32px;">
        <div style="display: inline-block; background: #661ae6; border-radius: 12px; padding: 12px; margin-bottom: 16px;">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
        </div>
        <h1 style="font-size: 24px; font-weight: 700; margin: 0;">PQC PKI Platform</h1>
      </div>
      <div style="background: #f8f9fa; border-radius: 12px; padding: 32px; text-align: center; margin-bottom: 24px;">
        <p style="font-size: 14px; color: #6b7280; margin: 0 0 16px;">Your email verification code is:</p>
        <div style="font-size: 36px; font-weight: 700; letter-spacing: 8px; color: #661ae6; font-family: monospace;">#{code}</div>
        <p style="font-size: 12px; color: #9ca3af; margin: 16px 0 0;">This code expires in 10 minutes.</p>
      </div>
      <p style="font-size: 13px; color: #9ca3af; text-align: center;">If you did not request this code, you can safely ignore this email.</p>
    </body>
    </html>
    """
  end

  def admin_credentials(tenant_name, ca_username, ca_password, ra_username, ra_password, ca_portal_url, ra_portal_url) do
    """
    <!DOCTYPE html>
    <html>
    <head><meta charset="utf-8"></head>
    <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 560px; margin: 0 auto; padding: 40px 20px; color: #1a1a2e;">
      <div style="text-align: center; margin-bottom: 32px;">
        <div style="display: inline-block; background: #661ae6; border-radius: 12px; padding: 12px; margin-bottom: 16px;">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
        </div>
        <h1 style="font-size: 24px; font-weight: 700; margin: 0;">PQC PKI Platform</h1>
      </div>

      <p style="font-size: 15px; margin-bottom: 24px;">Your tenant <strong>#{tenant_name}</strong> has been provisioned. Below are the administrator credentials for your CA and RA portals.</p>

      <div style="background: #fef3c7; border: 1px solid #f59e0b; border-radius: 8px; padding: 12px 16px; margin-bottom: 24px;">
        <p style="font-size: 13px; color: #92400e; margin: 0; font-weight: 600;">These credentials expire in 24 hours. Please log in and change your password immediately.</p>
      </div>

      <div style="background: #f8f9fa; border-radius: 12px; padding: 24px; margin-bottom: 16px;">
        <h2 style="font-size: 14px; font-weight: 600; color: #661ae6; margin: 0 0 12px; text-transform: uppercase; letter-spacing: 1px;">CA Administrator</h2>
        <table style="width: 100%; font-size: 14px;">
          <tr><td style="color: #6b7280; padding: 4px 0; width: 100px;">Portal:</td><td><a href="#{ca_portal_url}" style="color: #661ae6;">#{ca_portal_url}</a></td></tr>
          <tr><td style="color: #6b7280; padding: 4px 0;">Username:</td><td style="font-family: monospace; font-weight: 600;">#{ca_username}</td></tr>
          <tr><td style="color: #6b7280; padding: 4px 0;">Password:</td><td style="font-family: monospace; font-weight: 600;">#{ca_password}</td></tr>
        </table>
      </div>

      <div style="background: #f8f9fa; border-radius: 12px; padding: 24px; margin-bottom: 24px;">
        <h2 style="font-size: 14px; font-weight: 600; color: #661ae6; margin: 0 0 12px; text-transform: uppercase; letter-spacing: 1px;">RA Administrator</h2>
        <table style="width: 100%; font-size: 14px;">
          <tr><td style="color: #6b7280; padding: 4px 0; width: 100px;">Portal:</td><td><a href="#{ra_portal_url}" style="color: #661ae6;">#{ra_portal_url}</a></td></tr>
          <tr><td style="color: #6b7280; padding: 4px 0;">Username:</td><td style="font-family: monospace; font-weight: 600;">#{ra_username}</td></tr>
          <tr><td style="color: #6b7280; padding: 4px 0;">Password:</td><td style="font-family: monospace; font-weight: 600;">#{ra_password}</td></tr>
        </table>
      </div>

      <div style="font-size: 13px; color: #6b7280;">
        <p><strong>Instructions:</strong></p>
        <ol style="padding-left: 20px;">
          <li>Click the portal link above for CA or RA</li>
          <li>Log in with the provided username and password</li>
          <li>You will be prompted to change your password immediately</li>
          <li>After changing your password, you can begin managing your CA/RA</li>
        </ol>
      </div>

      <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 24px 0;" />
      <p style="font-size: 12px; color: #9ca3af; text-align: center;">This is an automated message from PQC PKI Platform. Do not reply to this email.</p>
    </body>
    </html>
    """
  end
end
