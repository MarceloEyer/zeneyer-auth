<?php
namespace ZenEyer\Auth\Auth; // <--- Namespace correto

use WP_Error;

class Google_Provider {

    /**
     * Valida o ID Token enviado pelo React e loga/cria o usuário.
     */
    public static function login_with_token($id_token) {
        $options = get_option('zeneyer_auth_settings');
        $client_id = isset($options['google_client_id']) ? $options['google_client_id'] : '';

        if (empty($client_id)) {
            return new WP_Error('google_config_error', 'Google Client ID não configurado no WordPress.', ['status' => 500]);
        }

        // Valida token direto na API do Google
        $response = wp_remote_get("https://oauth2.googleapis.com/tokeninfo?id_token=" . $id_token);

        if (is_wp_error($response)) {
            return new WP_Error('google_connection_error', 'Não foi possível conectar ao Google.', ['status' => 502]);
        }

        $body = json_decode(wp_remote_retrieve_body($response), true);

        if (isset($body['error']) || empty($body['email'])) {
            return new WP_Error('google_invalid_token', 'Token do Google inválido ou expirado.', ['status' => 401]);
        }

        // Segurança: O token é para o nosso app?
        if ($body['aud'] !== $client_id) {
            return new WP_Error('google_client_mismatch', 'Token não pertence a esta aplicação.', ['status' => 403]);
        }

        $email = sanitize_email($body['email']);
        $name = isset($body['name']) ? sanitize_text_field($body['name']) : '';
        $google_user_id = sanitize_text_field($body['sub']);

        // Login / Cadastro Lógica
        $user = get_user_by('email', $email);

        if (!$user) {
            if (!get_option('users_can_register')) {
                return new WP_Error('registration_disabled', 'Registro desativado.', ['status' => 403]);
            }

            $random_password = wp_generate_password(20);
            $user_id = wp_create_user($email, $random_password, $email);
            
            if (is_wp_error($user_id)) {
                return $user_id;
            }

            wp_update_user([
                'ID' => $user_id, 
                'display_name' => $name,
                'first_name' => isset($body['given_name']) ? $body['given_name'] : '',
                'last_name' => isset($body['family_name']) ? $body['family_name'] : ''
            ]);
            
            $user = get_user_by('id', $user_id);
        }

        update_user_meta($user->ID, 'zeneyer_google_id', $google_user_id);

        return $user;
    }
}
