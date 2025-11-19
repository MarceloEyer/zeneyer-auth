<?php
/**
 * JWT Management Class
 *
 * Responsável pela criação, assinatura e validação dos tokens.
 * Wrapper seguro para a biblioteca firebase/php-jwt.
 *
 * @package    ZenEyer_Auth
 * @subpackage ZenEyer_Auth/Core
 */

namespace ZenEyer\Auth\Core;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use WP_Error;

class JWT_Manager {

	/**
	 * Algoritmo de criptografia.
	 * HS256 é o padrão da indústria para chaves simétricas.
	 * Não damos opção de mudar para evitar configurações inseguras.
	 */
	const ALGORITHM = 'HS256';

	/**
	 * Gera um token JWT para um usuário específico.
	 *
	 * @param \WP_User $user Objeto do usuário WordPress.
	 * @return string|WP_Error Token assinado ou erro.
	 */
	public static function create_token( $user ) {
		$secret_key = self::get_secret_key();
		$issued_at  = time();
		$expiration = $issued_at + ( DAY_IN_SECONDS * 7 ); // Padrão: 7 dias
		$issuer     = get_bloginfo( 'url' ); // Quem emitiu o token (este site)

		if ( empty( $secret_key ) ) {
			return new WP_Error( 'jwt_config_error', 'A chave secreta JWT não está configurada.', array( 'status' => 500 ) );
		}

		$payload = array(
			'iss'  => $issuer,
			'iat'  => $issued_at,
			'nbf'  => $issued_at, // Not Before: Token não vale antes de agora
			'exp'  => $expiration,
			'data' => array(
				'user_id' => $user->ID,
				'email'   => $user->user_email, // Útil para debug no frontend
			),
		);

		/**
		 * Filtro para permitir modificação do payload.
		 * Ex: Adicionar roles ou custom claims sem mexer no core do plugin.
		 */
		$payload = apply_filters( 'zeneyer_auth_jwt_payload', $payload, $user );

		try {
			// A mágica acontece aqui: codificação e assinatura
			return JWT::encode( $payload, $secret_key, self::ALGORITHM );
		} catch ( \Exception $e ) {
			return new WP_Error( 'jwt_generation_error', $e->getMessage(), array( 'status' => 500 ) );
		}
	}

	/**
	 * Valida um token recebido (geralmente do header Authorization).
	 *
	 * @param string $token O token JWT (sem o prefixo Bearer).
	 * @return object|WP_Error Payload decodificado ou erro.
	 */
	public static function validate_token( $token ) {
		$secret_key = self::get_secret_key();

		try {
			// Decodifica e valida assinatura e expiração automaticamente
			$decoded = JWT::decode( $token, new Key( $secret_key, self::ALGORITHM ) );

			// Verificação extra: O usuário ainda existe?
			if ( ! isset( $decoded->data->user_id ) || ! get_userdata( $decoded->data->user_id ) ) {
				return new WP_Error( 'jwt_invalid_user', 'Usuário associado ao token não existe mais.', array( 'status' => 401 ) );
			}

			return $decoded;

		} catch ( \Firebase\JWT\ExpiredException $e ) {
			return new WP_Error( 'jwt_expired', 'O token expirou. Por favor, faça login novamente.', array( 'status' => 401 ) );
		} catch ( \Firebase\JWT\SignatureInvalidException $e ) {
			return new WP_Error( 'jwt_invalid_signature', 'A assinatura do token é inválida.', array( 'status' => 401 ) );
		} catch ( \Exception $e ) {
			return new WP_Error( 'jwt_invalid_token', 'Token inválido ou malformado.', array( 'status' => 401 ) );
		}
	}

	/**
	 * Obtém o segredo JWT de forma hierárquica.
	 * 1. wp-config.php (Mais seguro, não alterável via admin)
	 * 2. Banco de dados (Gerado automaticamente na ativação)
	 *
	 * @return string
	 */
	private static function get_secret_key() {
		if ( defined( 'ZENEYER_JWT_SECRET' ) ) {
			return ZENEYER_JWT_SECRET;
		}

		return get_option( 'zeneyer_auth_jwt_secret' );
	}
}
