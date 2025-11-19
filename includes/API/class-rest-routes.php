<?php
/**
 * REST API Routes (Versão Blindada v1.1)
 *
 * Inclui Rate Limiting, Validação de Senha e Endpoints de Perfil.
 */

namespace ZenEyer\Auth\API;

use ZenEyer\Auth\Core\JWT_Manager;
use ZenEyer\Auth\Auth\Google_Provider;
use WP_REST_Request;
use WP_REST_Server;
use WP_Error;

class Rest_Routes {

    const NAMESPACE = 'zeneyer/v1';

    public static function register_routes() {
        
        // 1. Login (Com Rate Limit)
        register_rest_route( self::NAMESPACE, '/auth/login', array(
            'methods'             => WP_REST_Server::CREATABLE,
            'callback'            => array( __CLASS__, 'login' ),
            'permission_callback' => '__return_true',
        ) );

        // 2. Register (Com validação forte)
        register_rest_route( self::NAMESPACE, '/auth/register', array(
            'methods'             => WP_REST_Server::CREATABLE,
            'callback'            => array( __CLASS__, 'register' ),
            'permission_callback' => '__return_true',
        ) );

        // 3. Google Login
        register_rest_route( self::NAMESPACE, '/auth/google', array(
            'methods'             => WP_REST_Server::CREATABLE,
            'callback'            => array( __CLASS__, 'google_login' ),
            'permission_callback' => '__return_true',
        ) );

        // 4. Validate Token
        register_rest_route( self::NAMESPACE, '/auth/validate', array(
            'methods'             => WP_REST_Server::CREATABLE,
            'callback'            => array( __CLASS__, 'validate' ),
            'permission_callback' => '__return_true',
        ) );

        // 5. Get Current User Profile (NOVO!)
        register_rest_route( self::NAMESPACE, '/auth/me', array(
            'methods'             => \WP_REST_Server::READABLE,
            'callback'            => array( __CLASS__, 'get_current_user' ),
            'permission_callback' => array( __CLASS__, 'check_auth' ), // Protegido
        ) );
        
        // 6. Settings
        register_rest_route( self::NAMESPACE, '/settings', array(
            'methods'             => \WP_REST_Server::READABLE,
            'callback'            => array( __CLASS__, 'get_public_settings' ),
            'permission_callback' => '__return_true',
        ) );
    }

    /**
     * Rate Limiter Minimalista
     * Bloqueia IP após 5 tentativas falhas por 10 minutos.
     */
    private static function check_rate_limit( $ip ) {
        $transient_name = 'zen_login_limit_' . md5( $ip );
        $attempts = get_transient( $transient_name );

        if ( $attempts && $attempts >= 5 ) {
            return new WP_Error( 'too_many_attempts', 'Muitas tentativas de login. Tente novamente em 10 minutos.', array( 'status' => 429 ) );
        }
        return true;
    }

    private static function increment_rate_limit( $ip ) {
        $transient_name = 'zen_login_limit_' . md5( $ip );
        $attempts = (int) get_transient( $transient_name );
        set_transient( $transient_name, $attempts + 1, 10 * MINUTE_IN_SECONDS );
    }

    // --- HANDLERS ---

    public static function login( WP_REST_Request $request ) {
        $ip = $_SERVER['REMOTE_ADDR'];
        
        // 1. Verifica Rate Limit
        $limit_check = self::check_rate_limit( $ip );
        if ( is_wp_error( $limit_check ) ) return $limit_check;

        $email    = sanitize_email( $request->get_param( 'email' ) );
        $password = $request->get_param( 'password' );

        if ( empty( $email ) || empty( $password ) ) {
            return new WP_Error( 'missing_credentials', 'Email e senha são obrigatórios.', array( 'status' => 400 ) );
        }

        $user = get_user_by( 'email', $email );

        if ( ! $user || ! wp_check_password( $password, $user->data->user_pass, $user->ID ) ) {
            // Incrementa erro no rate limit
            self::increment_rate_limit( $ip );
            return new WP_Error( 'invalid_credentials', 'Credenciais inválidas.', array( 'status' => 403 ) );
        }

        return self::generate_auth_response( $user );
    }

    public static function register( WP_REST_Request $request ) {
        if ( ! get_option( 'users_can_register' ) ) {
            return new WP_Error( 'registration_disabled', 'O registro está desativado.', array( 'status' => 403 ) );
        }

        $email = sanitize_email( $request->get_param( 'email' ) );
        $name  = sanitize_text_field( $request->get_param( 'name' ) );
        $pass  = $request->get_param( 'password' );

        // Validações de Segurança
        if ( ! is_email( $email ) ) {
            return new WP_Error( 'invalid_email', 'Email inválido.', array( 'status' => 400 ) );
        }
        if ( strlen( $pass ) < 6 ) {
            return new WP_Error( 'weak_password', 'A senha deve ter pelo menos 6 caracteres.', array( 'status' => 400 ) );
        }
        if ( email_exists( $email ) ) {
            return new WP_Error( 'email_exists', 'Email já cadastrado.', array( 'status' => 409 ) );
        }

        $user_id = wp_create_user( $email, $pass, $email );

        if ( is_wp_error( $user_id ) ) return $user_id;

        if ( ! empty( $name ) ) {
            wp_update_user( array( 'ID' => $user_id, 'display_name' => $name ) );
        }

        $user = get_user_by( 'id', $user_id );
        return self::generate_auth_response( $user );
    }

    // --- PERFIL ---

    /**
     * Middleware de Autenticação
     */
    public static function check_auth( WP_REST_Request $request ) {
        $token = $request->get_header( 'authorization' );
        if ( empty( $token ) ) return false;
        $token = str_replace( 'Bearer ', '', $token );
        $decoded = JWT_Manager::validate_token( $token );
        if ( is_wp_error( $decoded ) ) return false;
        
        // Injeta o user ID no request para usar depois
        $request->set_param( 'authenticated_user_id', $decoded->data->user_id );
        return true;
    }

    public static function get_current_user( WP_REST_Request $request ) {
        $user_id = $request->get_param( 'authenticated_user_id' );
        $user = get_user_by( 'id', $user_id );

        if ( ! $user ) return new WP_Error( 'user_not_found', 'Usuário não encontrado', array( 'status' => 404 ) );

        return array(
            'success' => true,
            'data' => array(
                'id' => $user->ID,
                'email' => $user->user_email,
                'display_name' => $user->display_name,
                'roles' => $user->roles,
                'avatar' => get_avatar_url( $user->ID )
            )
        );
    }

    // --- OUTROS (Google, Validate, Settings) mantidos iguais ao anterior ---
    // ... (Copie as funções google_login, validate, get_public_settings do código anterior aqui)
    // Para economizar espaço na resposta, assuma que elas continuam aqui.
    
    // Re-incluindo as funções vitais para o código funcionar completo:
    public static function google_login( WP_REST_Request $request ) {
        $token = $request->get_param( 'id_token' );
        if ( empty( $token ) ) return new WP_Error( 'no_token', 'Google ID Token obrigatório.', array( 'status' => 400 ) );

        if ( ! class_exists( 'ZenEyer\Auth\Auth\Google_Provider' ) ) {
             $plugin_dir = plugin_dir_path( dirname( __DIR__ ) );
             if ( file_exists( $plugin_dir . 'includes/Auth/class-google-provider.php' ) ) {
                 require_once $plugin_dir . 'includes/Auth/class-google-provider.php';
             }
        }
        $user = Google_Provider::login_with_token( $token );
        if ( is_wp_error( $user ) ) return $user;
        return self::generate_auth_response( $user );
    }

    public static function validate( WP_REST_Request $request ) {
        $token = $request->get_header( 'authorization' );
        if ( empty( $token ) ) return new WP_Error( 'no_token', 'Token ausente', array( 'status' => 401 ) );
        $token = str_replace( 'Bearer ', '', $token );
        $decoded = JWT_Manager::validate_token( $token );
        if ( is_wp_error( $decoded ) ) return $decoded;
        return array( 'success' => true, 'data' => array( 'user_id' => $decoded->data->user_id ) );
    }
    
    public static function get_public_settings() {
        $options = get_option('zeneyer_auth_settings');
        return array( 'success' => true, 'data' => array( 'google_client_id' => isset($options['google_client_id']) ? $options['google_client_id'] : '' ) );
    }

    private static function generate_auth_response( $user ) {
        $token = JWT_Manager::create_token( $user );
        if ( is_wp_error( $token ) ) return $token;
        return array(
            'success' => true,
            'data'    => array(
                'token' => $token,
                'user'  => array(
                    'id'           => $user->ID,
                    'email'        => $user->user_email,
                    'display_name' => $user->display_name,
                    'roles'        => $user->roles,
                    'avatar'       => get_avatar_url( $user->ID ),
                )
            )
        );
    }
}
