<?php
/**
 * Plugin Name:       ZenEyer Auth
 * Plugin URI:        https://github.com/zeneyer/auth-plugin
 * Description:       A minimalist, high-performance JWT Authentication plugin designed specifically for Headless WordPress & React applications.
 * Version:           1.1.0
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

define( 'ZENEYER_AUTH_VERSION', '1.1.0' );
define( 'ZENEYER_AUTH_PATH', plugin_dir_path( __FILE__ ) );
define( 'ZENEYER_AUTH_URL', plugin_dir_url( __FILE__ ) );

// 1. Carrega Bibliotecas Externas (Firebase JWT)
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

	/**
	 * Carrega todos os arquivos necessários manualmente.
	 * Isso evita erros 500 de "Class not found".
	 */
	private function load_dependencies() {
        // A. Core & Utils
        $this->load_file( 'includes/class-activator.php' );
        
        // B. O Cérebro (JWT Manager) - CRÍTICO
        $this->load_file( 'includes/Core/class-jwt-manager.php' );

        // C. Autenticação (Google)
        $this->load_file( 'includes/Auth/class-google-provider.php' );

        // D. API (Rotas)
        $this->load_file( 'includes/API/class-rest-routes.php' );

        // E. Admin (Tela de Configurações)
        $this->load_file( 'includes/admin/class-settings-page.php' );
	}

    /**
     * Helper para carregar arquivos com verificação
     */
    private function load_file( $path ) {
        if ( file_exists( ZENEYER_AUTH_PATH . $path ) ) {
            require_once ZENEYER_AUTH_PATH . $path;
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

        // Registra Menu de Admin
        if ( is_admin() && class_exists( 'ZenEyer\Auth\Admin\Settings_Page' ) ) {
            $settings = new \ZenEyer\Auth\Admin\Settings_Page();
            $settings->init();
        }
	}
}

ZenEyer_Auth_Init::get_instance();
