<?php
/**
 * Fired when the plugin is uninstalled.
 *
 * @package ZenEyer_Auth
 */

// Se o arquivo não for chamado pelo WordPress, morra.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	die;
}

// 1. Apagar as configurações do plugin
delete_option( 'zeneyer_auth_settings' );
delete_option( 'zeneyer_auth_jwt_secret' );

// 2. Apagar Transients (tokens de reset de senha pendentes)
global $wpdb;
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_zen_reset_%'" );
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_zen_reset_%'" );
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_zen_login_limit_%'" );
