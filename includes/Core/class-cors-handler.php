<?php
/**
 * CORS Handler para Headless WordPress
 * 
 * Adicionar à pasta: includes/Core/class-cors-handler.php
 * Carregar em: zeneyer-auth.php
 */

namespace ZenEyer\Auth\Core;

class CORS_Handler {
    
    public static function init() {
        // Permite OPTIONS preflight requests
        add_action('rest_api_init', [__CLASS__, 'add_cors_headers'], 15);
        
        // Handle OPTIONS requests antes do WordPress processar
        if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
            self::handle_preflight();
        }
    }
    
    public static function add_cors_headers() {
        remove_filter('rest_pre_serve_request', 'rest_send_cors_headers');
        
        add_filter('rest_pre_serve_request', function($served) {
            $allowed_origins = apply_filters('zeneyer_auth_cors_origins', [
                'http://localhost:5173', // Vite dev
                'http://localhost:3000', // React dev
                'https://djzeneyer.com'  // Produção
            ]);
            
            $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
            
            if (in_array($origin, $allowed_origins) || $origin === get_site_url()) {
                header("Access-Control-Allow-Origin: {$origin}");
                header('Access-Control-Allow-Credentials: true');
            }
            
            header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
            header('Access-Control-Allow-Headers: Authorization, Content-Type, X-WP-Nonce');
            header('Access-Control-Max-Age: 86400'); // Cache por 24h
            
            return $served;
        });
    }
    
    private static function handle_preflight() {
        self::add_cors_headers();
        status_header(200);
        exit;
    }
}
