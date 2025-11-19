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
        // Gera o texto dinâmico com a URL real do site
        $api_url = get_rest_url(null, 'zeneyer/v1');
        $ai_prompt = "
# ZenEyer Auth API Contract (Headless WordPress)

**Base URL:** `{$api_url}`
**Auth Method:** Bearer Token (JWT)

## 📡 Endpoints

| Method | Endpoint | Body / Params | Description |
| :--- | :--- | :--- | :--- |
| **GET** | `/settings` | *None* | Get public configs (e.g., `google_client_id`). |
| **POST** | `/auth/login` | `{ email, password }` | Login with credentials. Returns JWT + User. |
| **POST** | `/auth/register` | `{ email, password, name }` | Create account. Returns JWT + User. |
| **POST** | `/auth/google` | `{ id_token }` | Send Google OIDC token. Returns JWT + User. |
| **POST** | `/auth/validate` | *Header: Bearer Token* | Verify if token is still valid. |
| **GET** | `/auth/me` | *Header: Bearer Token* | Get current user profile (ID, Role, Avatar). |

## 🧠 Frontend Logic (React/Vite)
1. **Init:** Call `/settings` to fetch `google_client_id`. Initialize `GoogleOAuthProvider`.
2. **Session:** On load, check `localStorage`. If token exists, call `/auth/validate`.
3. **Google:** Use `@react-oauth/google`. On success, send `credential` to `/auth/google`.
4. **Security:** If API returns `401` or `403`, clear localStorage and redirect to login.
";
        ?>
        <div class="wrap">
            <h1>🔐 ZenEyer Auth</h1>
            
            <div style="display: flex; gap: 20px; flex-wrap: wrap;">
                
                <div style="flex: 1; min-width: 300px; background: #fff; padding: 20px; border: 1px solid #ccd0d4; box-shadow: 0 1px 1px rgba(0,0,0,.04);">
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
                    <h2 style="margin-top: 0;">🤖 AI & Developer Context</h2>
                    <p>Copie o texto abaixo e cole no <strong>ChatGPT, Claude ou Gemini</strong> para que eles criem o Frontend para você automaticamente.</p>
                    
                    <textarea id="ai-prompt" style="width: 100%; height: 300px; font-family: monospace; font-size: 12px; background: #fff;" readonly><?php echo trim($ai_prompt); ?></textarea>
                    
                    <p>
                        <button type="button" class="button button-primary" onclick="copyPrompt()">Copiar Contexto para IA</button>
                        <span id="copy-msg" style="margin-left: 10px; color: green; display: none;">Copiado!</span>
                    </p>
                </div>
            </div>

            <script>
            function copyPrompt() {
                var copyText = document.getElementById("ai-prompt");
                copyText.select();
                document.execCommand("copy");
                document.getElementById("copy-msg").style.display = "inline";
                setTimeout(function() {
                    document.getElementById("copy-msg").style.display = "none";
                }, 2000);
            }
            </script>
        </div>
        <?php
    }
}
