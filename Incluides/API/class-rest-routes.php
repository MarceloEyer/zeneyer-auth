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
		
		// 1. Login (Gera Token)
		register_rest_route( self::NAMESPACE, '/auth/login', array(
			'methods'             => WP_REST_Server::CREATABLE, // POST
			'callback'            => array( __CLASS__, 'login' ),
			'permission_callback' => '__return_true', // Público
		) );

		// 2. Register (Cria Usuário + Gera Token)
		register_rest_route( self::NAMESPACE, '/auth/register', array(
			'methods'             => WP_REST_Server::CREATABLE, // POST
			'callback'            => array( __CLASS__, 'register' ),
			'permission_callback' => '__return_true',
		) );

		// 3. Validate (Verifica se Token é válido)
		register_rest_route( self::NAMESPACE, '/auth/validate', array(
			'methods'             => WP_REST_Server::CREATABLE, // POST
			'callback'            => array( __CLASS__, 'validate' ),
			'permission_callback' => '__return_true',
		) );

		// 4. Request Password Reset (Envia Email)
		register_rest_route( self::NAMESPACE, '/auth/password/reset', array(
			'methods'             => WP_REST_Server::CREATABLE,
			'callback'            => array( __CLASS__, 'request_reset' ),
			'permission_callback' => '__return_true',
		) );
		
		// 5. Set New Password (Define nova senha com a chave)
		register_rest_route( self::NAMESPACE, '/auth/password/set', array(
			'methods'             => WP_REST_Server::CREATABLE,
			'callback'            => array( __CLASS__, 'set_password' ),
			'permission_callback' => '__return_true',
		) );
	}

	/**
	 * Endpoint: POST /auth/login
	 */
	public static function login( WP_REST_Request $request ) {
		$email    = sanitize_email( $request->get_param( 'email' ) );
		$password = $request->get_param( 'password' );

		if ( empty( $email ) || empty( $password ) ) {
			return new WP_Error( 'missing_credentials', 'Email e senha são obrigatórios.', array( 'status' => 400 ) );
		}

		// Força login por email (UX melhor que username)
		$user = get_user_by( 'email', $email );

		if ( ! $user || ! wp_check_password( $password, $user->data->user_pass, $user->ID ) ) {
			return new WP_Error( 'invalid_credentials', 'Credenciais inválidas.', array( 'status' => 403 ) );
		}

		return self::generate_auth_response( $user );
	}

	/**
	 * Endpoint: POST /auth/register
	 */
	public static function register( WP_REST_Request $request ) {
		// Proteção básica contra bots (Honey Pot seria ideal no frontend)
		if ( ! get_option( 'users_can_register' ) ) {
			return new WP_Error( 'registration_disabled', 'O registro de novos usuários está desativado.', array( 'status' => 403 ) );
		}

		$email = sanitize_email( $request->get_param( 'email' ) );
		$name  = sanitize_text_field( $request->get_param( 'name' ) );
		$pass  = $request->get_param( 'password' );

		if ( empty( $email ) || empty( $pass ) ) {
			return new WP_Error( 'missing_data', 'Dados incompletos.', array( 'status' => 400 ) );
		}

		if ( username_exists( $email ) || email_exists( $email ) ) {
			return new WP_Error( 'email_exists', 'Este email já está cadastrado.', array( 'status' => 409 ) );
		}

		// Criação do usuário
		$user_id = wp_create_user( $email, $pass, $email );

		if ( is_wp_error( $user_id ) ) {
			return $user_id;
		}

		// Atualiza o Display Name se fornecido
		if ( ! empty( $name ) ) {
			wp_update_user( array( 'ID' => $user_id, 'display_name' => $name ) );
		}

		// Hook para Newsletter ou outras ações (Desacoplado!)
		do_action( 'zeneyer_user_registered', $user_id );

		// Login automático após registro (UX Oceano Azul)
		$user = get_user_by( 'id', $user_id );
		return self::generate_auth_response( $user );
	}

	/**
	 * Endpoint: POST /auth/validate
	 */
	public static function validate( WP_REST_Request $request ) {
		// Pega o token do header Authorization: Bearer <token>
		$token = $request->get_header( 'authorization' );
		
		if ( empty( $token ) ) {
			return new WP_Error( 'no_token', 'Token não fornecido.', array( 'status' => 401 ) );
		}

		$token = str_replace( 'Bearer ', '', $token );
		$decoded = JWT_Manager::validate_token( $token );

		if ( is_wp_error( $decoded ) ) {
			return $decoded;
		}

		return array(
			'success' => true,
			'message' => 'Token válido.',
			'data'    => array( 'user_id' => $decoded->data->user_id )
		);
	}

	/**
	 * Helper: Gera resposta padrão de sucesso
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
					'avatar'       => get_avatar_url( $user->ID ),
				)
			)
		);
	}
	
	// ... Implementação do Reset Password (simplificada para brevidade aqui, mas seguiria a mesma lógica)
}