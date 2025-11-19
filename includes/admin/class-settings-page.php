<?php
namespace ZenEyer\Auth\Admin;

class Settings_Page {

    private $option_name = 'zeneyer_auth_settings';

    public function init() {
        add_action('admin_menu', [$this, 'add_admin_menu']);
        add_action('admin_init', [$this, 'register_settings']);
    }

    public function add_admin_menu() {
        add_options_page(
            'ZenEyer Auth',
            'ZenEyer Auth',
            'manage_options',
            'zeneyer-auth',
            [$this, 'render_page']
        );
    }

    public function register_settings() {
        register_setting($this->option_name, $this->option_name);

        add_settings_section(
            'zeneyer_google_section',
            'Configurações Gerais',
            null,
            'zeneyer-auth'
        );

        add_settings_field(
            'google_client_id',
            'Google Client ID',
            [$this, 'render_field_input'],
            'zeneyer-auth',
            'zeneyer_google_section',
            ['label_for' => 'google_client_id']
        );
    }

    public function render_field_input($args) {
        $options = get_option($this->option_name);
        $val = isset($options[$args['label_for']]) ? $options[$args['label_for']] : '';
        echo '<input type="text" id="' . $args['label_for'] . '" name="' . $this->option_name . '[' . $args['label_for'] . ']" value="' . esc_attr($val) . '" class="regular-text code" style="width: 100%; max-width: 500px;">';
        echo '<p class="description">Pegue este ID no <a href="https://console.cloud.google.com/apis/credentials" target="_blank">Google Cloud Console</a>.</p>';
    }

    public function render_page() {
        $api_url = get_rest_url(null, 'zeneyer-auth/v1'); // Namespace NOVO
        
        $ai_prompt = "
# ZenEyer Auth API Contract (Headless WordPress)

**Base URL:** `{$api_url}`
**Auth Method:** Bearer Token (JWT)

## 📡 Endpoints
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| **GET** | `/settings` | Get public configs (Google ID). |
| **POST** | `/auth/login` | Login email/pass. |
| **POST** | `/auth/register` | Create account. |
| **POST** | `/auth/google` | Login with Google ID Token. |
| **POST** | `/auth/validate` | Verify JWT. |
| **GET** | `/auth/me` | Get profile. |
| **POST** | `/auth/password/reset` | Request reset code. |
| **POST** | `/auth/password/set` | Set new password. |
";
        ?>
        <div class="wrap">
            <h1>🔐 ZenEyer Auth <span style="font-size: 12px; background: #e5e7eb; padding: 2px 8px; border-radius: 10px; color: #374151;">v1.2</span></h1>
            
            <div style="display: flex; gap: 20px; flex-wrap: wrap;">
                <div style="flex: 1; min-width: 300px; background: #fff; padding: 20px; border: 1px solid #ccd0d4;">
                    <h2>Configuração</h2>
                    <form action="options.php" method="post">
                        <?php
                        settings_fields($this->option_name);
                        do_settings_sections('zeneyer-auth');
                        submit_button('Salvar Alterações');
                        ?>
                    </form>
                </div>
                <div style="flex: 1; min-width: 300px; background: #f0f0f1; padding: 20px; border: 1px solid #ccd0d4;">
                    <h2 style="margin-top: 0;">🤖 AI Context</h2>
                    <textarea id="ai-prompt" style="width: 100%; height: 300px; font-family: monospace; font-size: 12px;" readonly><?php echo trim($ai_prompt); ?></textarea>
                    <button type="button" class="button" onclick="document.getElementById('ai-prompt').select();document.execCommand('copy');">Copiar</button>
                </div>
            </div>
        </div>
        <?php
    }
}
