<?php

namespace ZenEyer\Auth;

/**
 * Fired during plugin activation.
 */
class Activator {

	/**
	 * Executa as tarefas iniciais e verificações de requisitos.
	 */
	public static function activate() {
		// 1. Verificações de Requisitos do Sistema
		self::check_requirements();

		// 2. Configuração Inicial
		self::generate_secret_key();
		self::create_log_table();
		
		// 3. Limpar regras de permalink para reconhecer as novas rotas API
		flush_rewrite_rules();
	}

	/**
	 * Verifica se o servidor tem o mínimo necessário.
	 * Se não tiver, impede a ativação e mostra mensagem amigável.
	 */
	private static function check_requirements() {
		$errors = [];

		// Checa Versão do PHP (7.4 é o nosso mínimo para segurança e performance)
		if ( version_compare( PHP_VERSION, '7.4', '<' ) ) {
			$errors[] = 'Sua versão do PHP é a <strong>' . PHP_VERSION . '</strong>, mas este plugin requer a versão <strong>7.4</strong> ou superior.';
		}

		// Checa OpenSSL (O Coração do JWT)
		if ( ! extension_loaded( 'openssl' ) ) {
			$errors[] = 'A extensão PHP <strong>OpenSSL</strong> não está ativa no seu servidor. Ela é essencial para criptografia segura.';
		}

		// Se houver erros, para tudo e avisa o usuário.
		if ( ! empty( $errors ) ) {
			$message = '<h3>🛑 Não foi possível ativar o ZenEyer Auth</h3>';
			$message .= '<p>Para garantir a segurança do seu site, precisamos dos seguintes requisitos:</p>';
			$message .= '<ul>';
			foreach ( $errors as $error ) {
				$message .= '<li>' . $error . '</li>';
			}
			$message .= '</ul>';
			$message .= '<p><em>Por favor, entre em contato com sua hospedagem (Hostinger, etc) e solicite a ativação desses recursos. É gratuito e rápido.</em></p>';
			$message .= '<p><a href="' . get_admin_url( null, 'plugins.php' ) . '" class="button">Voltar para Plugins</a></p>';

			// wp_die mata o processo e mostra essa tela HTML
			wp_die( $message, 'Requisitos não atendidos', array( 'back_link' => true ) );
		}
	}

	/**
	 * Gera o segredo se não existir.
	 */
	private static function generate_secret_key() {
		if ( defined( 'ZENEYER_JWT_SECRET' ) ) {
			return;
		}

		$saved_secret = get_option( 'zeneyer_auth_jwt_secret' );

		if ( ! $saved_secret ) {
			$secret = wp_generate_password( 64, true, true );
			add_option( 'zeneyer_auth_jwt_secret', $secret, '', 'yes' );
		}
	}

	private static function create_log_table() {
		// Futuro: Tabela de logs
	}
}