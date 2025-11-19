<?php
/**
 * REST API Routes
 *
 * Define e registra os endpoints da API.
 * Namespace: zeneyer/v1
 *
 * @package    ZenEyer_Auth
 * @subpackage ZenEyer_Auth/API
 */

namespace ZenEyer\Auth\API;

use ZenEyer\Auth\Core\JWT_Manager;
use ZenEyer\Auth\Auth\Google_Provider; // <--- Importante: Importando a classe do Google
use WP_REST_Request;
use WP_REST_Server;
use WP_Error;
use WP_User;

class Rest_Routes {

	const NAMESPACE = 'zeneyer/v1';

	/**
	 * Registra todas as rotas da API.
	 */
	public static function register_routes() {
		
		// 1. Login (Email/Senha)
		register_rest_route( self::NAMESPACE, '/auth/login', array(
			'methods'             => WP_REST_Server::CREATABLE, // POST
			'callback'            => array( __CLASS__, 'login' ),
			'permission_callback' => '__return_true',
		) );

		// 2. Register (Email/Senha)
		register_rest_route( self::NAMESPACE, '/auth/register', array(
			'methods'             => WP_REST_Server::CREATABLE, // POST
			'callback'            => array( __CLASS__, 'register' ),
			'permission_callback' => '__return_true',
		) );

		// 3. Google Login (O que estava faltando!)
		register_rest_route( self::NAMESPACE, '/auth/google', array(
			'methods'             => WP_REST_Server::CREATABLE, // POST
			'callback'            => array( __CLASS__, 'google_login' ),
			'permission_callback' => '__return_true',
		) );

		// 4. Validate Token
		register_rest_route( self::NAMESPACE, '/auth/validate', array(
			'methods'             => WP_REST_Server::CREATABLE, // POST
			'callback'            => array( __CLASS__, 'validate' ),
			'permission_callback' => '__return_true',
		) );

        // 5. Settings (Para o Frontend pegar o ID)
        register_rest_route( self::NAMESPACE, '/settings', array(
            'methods'             => \WP_REST_Server::READABLE, // GET
            'callback'            => array( __CLASS__, 'get_public_settings' ),
            'permission_callback' => '__return_true',
        ) );
	}

	/**
	 * Handler: Login Google
	 */
	public static function google_login( WP_REST_Request $request ) {
		$token = $request->get_param( 'id_token' );

		if ( empty( $token ) ) {
			return new WP_Error( 'no_token', 'Google ID Token é obrigatório.', array( 'status' => 400 ) );
		}

		// Chama a classe que criamos antes para validar no Google
		// Certifique-se que o arquivo includes/Auth/class-google-provider.php existe!
		if ( ! class_exists( 'ZenEyer\Auth\Auth\Google_Provider' ) ) {
		    // Fallback caso o autoloader ainda não tenha pego, tenta carregar manual
            $plugin_dir = plugin_dir_path( dirname( __DIR__ ) ); // sobe 2 niveis
            if ( file_exists( $plugin_dir . 'includes/Auth/class-google-provider.php' ) ) {
                require_once $plugin_dir . 'includes/Auth/class-google-provider.php';
            } else {
			    return new WP_Error( 'server_config_error', 'Classe Google Provider não encontrada.', array( 'status' => 500 ) );
            }
		}

		$user = Google_Provider::login_with_token( $token );

		if ( is_wp_error( $user ) ) {
			return $user;
		}

		return self::generate_auth_response( $user );
	}

	/**
	 * Handler: Login Normal
	 */
	public static function login( WP_REST_Request $request ) {
		$email    = sanitize_email( $request->get_param( 'email' ) );
		$password = $request->get_param( 'password' );

		if ( empty( $email ) || empty( $password ) ) {
			return new WP_Error( 'missing_credentials', 'Email e senha são obrigatórios.', array( 'status' => 400 ) );
		}

		$user = get_user_by( 'email', $email );

		if ( ! $user || ! wp_check_password( $password, $user->data->user_pass, $user->ID ) ) {
			return new WP_Error( 'invalid_credentials', 'Credenciais inválidas.', array( 'status' => 403 ) );
		}

		return self::generate_auth_response( $user );
	}

	/**
	 * Handler: Registro
	 */
	public static function register( WP_REST_Request $request ) {
		if ( ! get_option( 'users_can_register' ) ) {
			return new WP_Error( 'registration_disabled', 'O registro está desativado.', array( 'status' => 403 ) );
		}

		$email = sanitize_email( $request->get_param( 'email' ) );
		$name  = sanitize_text_field( $request->get_param( 'name' ) );
		$pass  = $request->get_param( 'password' );

		if ( empty( $email ) || empty( $pass ) ) {
			return new WP_Error( 'missing_data', 'Dados incompletos.', array( 'status' => 400 ) );
		}

		if ( username_exists( $email ) || email_exists( $email ) ) {
			return new WP_Error( 'email_exists', 'Email já cadastrado.', array( 'status' => 409 ) );
		}

		$user_id = wp_create_user( $email, $pass, $email );

		if ( is_wp_error( $user_id ) ) {
			return $user_id;
		}

		if ( ! empty( $name ) ) {
			wp_update_user( array( 'ID' => $user_id, 'display_name' => $name ) );
		}

		$user = get_user_by( 'id', $user_id );
		return self::generate_auth_response( $user );
	}

	/**
	 * Handler: Validate Token
	 */
	public static function validate( WP_REST_Request $request ) {
		$token = $request->get_header( 'authorization' );
		if ( empty( $token ) ) return new WP_Error( 'no_token', 'Token ausente', array( 'status' => 401 ) );
		
		$token = str_replace( 'Bearer ', '', $token );
		$decoded = JWT_Manager::validate_token( $token );

		if ( is_wp_error( $decoded ) ) return $decoded;

		return array( 'success' => true, 'data' => array( 'user_id' => $decoded->data->user_id ) );
	}

    /**
     * Handler: Configurações Públicas
     */
    public static function get_public_settings() {
        $options = get_option('zeneyer_auth_settings');
        return array(
            'success' => true,
            'data'    => array(
                'google_client_id' => isset($options['google_client_id']) ? $options['google_client_id'] : '',
            )
        );
    }

	/**
	 * Helper: Resposta Padrão
	 */
	private static function generate_auth_response( $user ) {
		$token = JWT_Manager::create_token( $user );

		if ( is_wp_error( $token ) ) {
			return $token;
		}

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
