<?php
/**
 * Plugin Name:       ZenEyer Auth
 * Plugin URI:        https://github.com/zeneyer/auth-plugin
 * Description:       A minimalist, high-performance JWT Authentication plugin designed specifically for Headless WordPress & React applications.
 * Version:           1.0.1
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            ZenEyer Team
 * Author URI:        https://zeneyer.com
 * License:           GPL v2 or later
 * Text Domain:       zeneyer-auth
 * Domain Path:       /languages
 *
 * @package           ZenEyer_Auth
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; 
}

define( 'ZENEYER_AUTH_VERSION', '1.0.1' );
define( 'ZENEYER_AUTH_PATH', plugin_dir_path( __FILE__ ) );
define( 'ZENEYER_AUTH_URL', plugin_dir_url( __FILE__ ) );

// Carrega o Autoloader do Composer
if ( file_exists( ZENEYER_AUTH_PATH . 'vendor/autoload.php' ) ) {
	require_once ZENEYER_AUTH_PATH . 'vendor/autoload.php';
}

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
        // 1. Carrega classes Core
        if ( file_exists( ZENEYER_AUTH_PATH . 'includes/class-activator.php' ) ) {
		    require_once ZENEYER_AUTH_PATH . 'includes/class-activator.php';
        }

        // 2. Carrega a API
        if ( file_exists( ZENEYER_AUTH_PATH . 'includes/API/class-rest-routes.php' ) ) {
		    require_once ZENEYER_AUTH_PATH . 'includes/API/class-rest-routes.php';
        }

        // 3. Carrega o Admin (Menu de Configurações) - NOVO!
        if ( file_exists( ZENEYER_AUTH_PATH . 'includes/admin/class-settings-page.php' ) ) {
            require_once ZENEYER_AUTH_PATH . 'includes/admin/class-settings-page.php';
        }
	}

	private function register_hooks() {
        // Registra Rotas API
        if ( class_exists( 'ZenEyer\Auth\API\Rest_Routes' ) ) {
		    add_action( 'rest_api_init', array( 'ZenEyer\Auth\API\Rest_Routes', 'register_routes' ) );
        }
		
        // Registra Ativador
        if ( class_exists( 'ZenEyer\Auth\Activator' ) ) {
		    register_activation_hook( __FILE__, array( 'ZenEyer\Auth\Activator', 'activate' ) );
        }

        // Registra Menu de Admin - NOVO!
        if ( class_exists( 'ZenEyer\Auth\Admin\Settings_Page' ) ) {
            $settings = new \ZenEyer\Auth\Admin\Settings_Page();
            $settings->init();
        }
	}
}

ZenEyer_Auth_Init::get_instance();
