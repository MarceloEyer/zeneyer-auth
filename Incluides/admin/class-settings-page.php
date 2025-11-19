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
            'Google OAuth 2.0',
            [$this, 'render_section_info'],
            'zeneyer-auth'
        );

        add_settings_field(
            'google_client_id',
            'Client ID',
            [$this, 'render_field_input'],
            'zeneyer-auth',
            'zeneyer_google_section',
            ['label_for' => 'google_client_id']
        );

        add_settings_field(
            'frontend_url',
            'URL do Frontend (React)',
            [$this, 'render_field_input'],
            'zeneyer-auth',
            'zeneyer_google_section',
            [
                'label_for' => 'frontend_url', 
                'description' => 'Usado para links de redefinição de senha (ex: https://seusite.com)'
            ]
        );
    }

    public function render_section_info() {
        echo '<div class="notice notice-info inline"><p>';
        echo 'Para ativar o Login com Google, acesse o <a href="https://console.cloud.google.com/apis/credentials" target="_blank">Google Cloud Console</a>.<br>';
        echo 'Crie uma credencial <strong>OAuth Client ID</strong> e adicione a URL do seu site nas origens permitidas.';
        echo '</p></div>';
    }

    public function render_field_input($args) {
        $options = get_option($this->option_name);
        $val = isset($options[$args['label_for']]) ? $options[$args['label_for']] : '';
        $desc = isset($args['description']) ? '<p class="description">' . $args['description'] . '</p>' : '';
        
        echo '<input type="text" id="' . $args['label_for'] . '" name="' . $this->option_name . '[' . $args['label_for'] . ']" value="' . esc_attr($val) . '" class="regular-text">';
        echo $desc;
    }

    public function render_page() {
        ?>
        <div class="wrap">
            <h1>🔐 ZenEyer Auth Configuration</h1>
            <form action="options.php" method="post">
                <?php
                settings_fields($this->option_name);
                do_settings_sections('zeneyer-auth');
                submit_button('Salvar Configurações');
                ?>
            </form>
            
            <hr>
            
            <h3>📚 Como usar no Frontend</h3>
            <div class="card">
                <p><strong>Endpoint de Login:</strong> <code>POST /wp-json/zeneyer/v1/auth/login</code></p>
                <p><strong>Endpoint do Google:</strong> <code>POST /wp-json/zeneyer/v1/auth/google</code></p>
                <p>Envie o <code>id_token</code> que você recebe do Google para este endpoint.</p>
            </div>
        </div>
        <?php
    }
}