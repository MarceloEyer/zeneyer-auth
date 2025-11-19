<?php
/**
 * Plugin Name:       ZenEyer Auth
 * Plugin URI:        https://github.com/zeneyer/auth-plugin
 * Description:       A minimalist, high-performance JWT Authentication plugin designed specifically for Headless WordPress & React applications.
 * Version:           1.0.0
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            ZenEyer Team
 * Author URI:        https://zeneyer.com
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       zeneyer-auth
 * Domain Path:       /languages
 *
 * @package           ZenEyer_Auth
 */

// 1. Segurança: Impede acesso direto ao arquivo
if ( ! defined( 'ABSPATH' ) ) {
	exit; // Silence is golden.
}

// 2. Define Constantes Globais do Plugin
define( 'ZENEYER_AUTH_VERSION', '1.0.0' );
define( 'ZENEYER_AUTH_PATH', plugin_dir_path( __FILE__ ) );
define( 'ZENEYER_AUTH_URL', plugin_dir_url( __FILE__ ) );

// 3. Carrega o Autoloader do Composer (se existir)
if ( file_exists( ZENEYER_AUTH_PATH . 'vendor/autoload.php' ) ) {
	require_once ZENEYER_AUTH_PATH . 'vendor/autoload.php';
}

/**
 * Classe principal que inicializa o plugin.
 * Usamos o padrão Singleton para evitar múltiplas instâncias.
 */
final class ZenEyer_Auth_Init {

	private static $instance = null;

	public static function get_instance() {
		if ( is_null( self::$instance ) ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		$this->load_dependencies();
		$this->register_hooks();
	}

	private function load_dependencies() {
		// Carregar classes principais manualmente se o autoloader falhar ou para ordem específica
		require_once ZENEYER_AUTH_PATH . 'includes/class-activator.php';
		require_once ZENEYER_AUTH_PATH . 'includes/API/class-rest-routes.php';
	}

	private function register_hooks() {
		// Registrar rotas da API REST
		add_action( 'rest_api_init', array( 'ZenEyer\Auth\API\Rest_Routes', 'register_routes' ) );
		
		// Hooks de ativação/desativação
		register_activation_hook( __FILE__, array( 'ZenEyer\Auth\Activator', 'activate' ) );
	}
}

// Iniciar o plugin
ZenEyer_Auth_Init::get_instance();