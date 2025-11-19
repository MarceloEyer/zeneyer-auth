<?php
namespace ZenEyer\Auth\API;

use ZenEyer\Auth\Core\JWT_Manager;
// Carregamento manual de dependências acontece dentro dos métodos para evitar erro 500

use WP_REST_Request;
use WP_REST_Server;
use WP_Error;

class Rest_Routes {

    const NAMESPACE = 'zeneyer/v1';

    public static function register_routes() {
        // 1. Login
        register_rest_route( self::NAMESPACE, '/auth/login', array(
            'methods'             => WP_REST_Server::CREATABLE,
            'callback'            => array( __CLASS__, 'login' ),
            'permission_callback' => '__return_true',
        ) );

        // 2. Register
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

        // 5. Get Profile (Me)
        register_rest_route( self::NAMESPACE, '/auth/me', array(
            'methods'             => \WP_REST_Server::READABLE,
            'callback'            => array( __CLASS__, 'get_current_user' ),
            'permission_callback' => array( __CLASS__, 'check_auth' ),
        ) );

        // 6. Settings
        register_rest_route( self::NAMESPACE, '/settings', array(
            'methods'             => \WP_REST_Server::READABLE,
            'callback'            => array( __CLASS__, 'get_public_settings' ),
            'permission_callback' => '__return_true',
        ) );

        // 7. Password Reset (Request)
        register_rest_route( self::NAMESPACE, '/auth/password/reset', array(
            'methods'             => WP_REST_Server::CREATABLE,
            'callback'            => array( __CLASS__, 'request_reset' ),
            'permission_callback' => '__return_true',
        ) );

        // 8. Password Reset (Set New)
        register_rest_route( self::NAMESPACE, '/auth/password/set', array(
            'methods'             => WP_REST_Server::CREATABLE,
            'callback'            => array( __CLASS__, 'set_new_password' ),
            'permission_callback' => '__return_true',
        ) );
    }

    // --- SEGURANÇA: RATE LIMIT ---
    private static function check_rate_limit( $ip ) {
        $transient_name = 'zen_login_limit_' . md5( $ip );
        $attempts = get_transient( $transient_name );
        if ( $attempts && $attempts >= 5 ) {
            return new WP_Error( 'too_many_attempts', 'Muitas tentativas. Aguarde 10 min.', array( 'status' => 429 ) );
        }
        return true;
    }

    private static function increment_rate_limit( $ip ) {
        $transient_name = 'zen_login_limit_' . md5( $ip );
        $attempts = (int) get_transient( $transient_name );
        set_transient( $transient_name, $attempts + 1, 10 * MINUTE_IN_SECONDS );
    }

    // --- HANDLERS DE AUTENTICAÇÃO ---

    public static function login( WP_REST_Request $request ) {
        $ip = $_SERVER['REMOTE_ADDR'];
        $limit = self::check_rate_limit($ip);
        if(is_wp_error($limit)) return $limit;

        $email = sanitize_email( $request->get_param( 'email' ) );
        $pass  = $request->get_param( 'password' );

        if ( empty( $email ) || empty( $pass ) ) return new WP_Error( 'missing_credentials', 'Dados incompletos.', array( 'status' => 400 ) );

        $user = get_user_by( 'email', $email );

        if ( ! $user || ! wp_check_password( $pass, $user->data->user_pass, $user->ID ) ) {
            self::increment_rate_limit($ip);
            return new WP_Error( 'invalid_credentials', 'Credenciais inválidas.', array( 'status' => 403 ) );
        }

        return self::generate_auth_response( $user );
    }

    public static function register( WP_REST_Request $request ) {
        if ( ! get_option( 'users_can_register' ) ) return new WP_Error( 'registration_disabled', 'Registro fechado.', array( 'status' => 403 ) );

        $email = sanitize_email( $request->get_param( 'email' ) );
        $name  = sanitize_text_field( $request->get_param( 'name' ) );
        $pass  = $request->get_param( 'password' );

        if ( ! is_email( $email ) ) return new WP_Error( 'invalid_email', 'Email inválido.', array( 'status' => 400 ) );
        if ( strlen( $pass ) < 6 ) return new WP_Error( 'weak_password', 'Senha curta (min 6).', array( 'status' => 400 ) );
        if ( email_exists( $email ) ) return new WP_Error( 'email_exists', 'Email já existe.', array( 'status' => 409 ) );

        $user_id = wp_create_user( $email, $pass, $email );
        if ( is_wp_error( $user_id ) ) return $user_id;
        if ( ! empty( $name ) ) wp_update_user( array( 'ID' => $user_id, 'display_name' => $name ) );

        return self::generate_auth_response( get_user_by( 'id', $user_id ) );
    }

    public static function google_login( WP_REST_Request $request ) {
        $token = $request->get_param( 'id_token' );
        if ( empty( $token ) ) return new WP_Error( 'no_token', 'Google Token obrigatório.', array( 'status' => 400 ) );

        // Carregamento seguro da classe
        if ( ! class_exists( 'ZenEyer\Auth\Auth\Google_Provider' ) ) {
            if ( defined( 'ZENEYER_AUTH_PATH' ) ) {
                require_once ZENEYER_AUTH_PATH . 'includes/Auth/class-google-provider.php';
            }
        }
        
        if ( ! class_exists( 'ZenEyer\Auth\Auth\Google_Provider' ) ) {
             return new WP_Error( 'class_not_found', 'Erro interno: Google Provider.', array( 'status' => 500 ) );
        }

        $user = \ZenEyer\Auth\Auth\Google_Provider::login_with_token( $token );
        if ( is_wp_error( $user ) ) return $user;

        return self::generate_auth_response( $user );
    }

    // --- UTILS & PROFILE ---

    public static function validate( WP_REST_Request $request ) {
        $token = $request->get_header( 'authorization' );
        if ( empty( $token ) ) return new WP_Error( 'no_token', 'Sem token', array( 'status' => 401 ) );
        
        $token = str_replace( 'Bearer ', '', $token );
        $decoded = JWT_Manager::validate_token( $token );

        if ( is_wp_error( $decoded ) ) return $decoded;
        return array( 'success' => true, 'data' => array( 'user_id' => $decoded->data->user_id ) );
    }

    public static function check_auth( WP_REST_Request $request ) {
        $token = $request->get_header( 'authorization' );
        if ( empty( $token ) ) return false;
        $token = str_replace( 'Bearer ', '', $token );
        $decoded = JWT_Manager::validate_token( $token );
        if ( is_wp_error( $decoded ) ) return false;
        $request->set_param( 'authenticated_user_id', $decoded->data->user_id );
        return true;
    }

    public static function get_current_user( WP_REST_Request $request ) {
        $user = get_user_by( 'id', $request->get_param( 'authenticated_user_id' ) );
        if ( ! $user ) return new WP_Error( 'not_found', 'User not found', array( 'status' => 404 ) );
        
        return array( 'success' => true, 'data' => array( 
            'id' => $user->ID, 
            'email' => $user->user_email, 
            'display_name' => $user->display_name, 
            'roles' => $user->roles, 
            'avatar' => get_avatar_url($user->ID) 
        ));
    }

    public static function get_public_settings() {
        $options = get_option('zeneyer_auth_settings');
        return array( 'success' => true, 'data' => array( 'google_client_id' => isset($options['google_client_id']) ? $options['google_client_id'] : '' ) );
    }

    // --- RECUPERAÇÃO DE SENHA ---

    public static function request_reset( WP_REST_Request $request ) {
        $email = sanitize_email( $request->get_param( 'email' ) );
        if ( ! is_email( $email ) ) return new WP_Error( 'invalid_email', 'Email inválido.', array( 'status' => 400 ) );

        $user = get_user_by( 'email', $email );
        
        // Segurança: Resposta genérica para não vazar emails
        if ( ! $user ) return array( 'success' => true, 'message' => 'Se o email existir, o código foi enviado.' );

        $code = wp_rand( 100000, 999999 );
        set_transient( 'zen_reset_' . $user->ID, $code, 15 * MINUTE_IN_SECONDS );

        $subject = 'Recuperação de Senha - ' . get_bloginfo( 'name' );
        $message = "Olá " . $user->display_name . ",\n\nSeu código: " . $code . "\n\nExpira em 15 minutos.";
        
        wp_mail( $email, $subject, $message );

        return array( 'success' => true, 'message' => 'Se o email existir, o código foi enviado.' );
    }

    public static function set_new_password( WP_REST_Request $request ) {
        $email = sanitize_email( $request->get_param( 'email' ) );
        $code  = sanitize_text_field( $request->get_param( 'code' ) );
        $pass  = $request->get_param( 'password' );

        if ( empty( $email ) || empty( $code ) || empty( $pass ) ) return new WP_Error( 'missing_data', 'Dados incompletos.', array( 'status' => 400 ) );

        $user = get_user_by( 'email', $email );
        if ( ! $user ) return new WP_Error( 'invalid_code', 'Erro no código.', array( 'status' => 400 ) );

        $saved_code = get_transient( 'zen_reset_' . $user->ID );
        if ( ! $saved_code || $saved_code != $code ) return new WP_Error( 'invalid_code', 'Código inválido ou expirado.', array( 'status' => 400 ) );

        if ( strlen( $pass ) < 6 ) return new WP_Error( 'weak_password', 'Senha muito curta.', array( 'status' => 400 ) );

        wp_set_password( $pass, $user->ID );
        delete_transient( 'zen_reset_' . $user->ID );

        return array( 'success' => true, 'message' => 'Senha alterada!' );
    }

    // --- HELPER ---

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
                    'name'         => $user->display_name, // Vital para React
                    'roles'        => $user->roles,
					'avatar'       => get_avatar_url( $user->ID ),
				)
			)
		);
	}
}
