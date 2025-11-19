=== ZenEyer Auth ===
Contributors: zeneyer
Tags: jwt, headless, authentication, react, rest api
Requires at least: 6.0
Tested up to: 6.4
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Minimalist, secure, and zero-config JWT Authentication for Headless WordPress.

== Description ==

ZenEyer Auth is an opinionated, high-performance authentication plugin designed specifically for **Headless WordPress** architectures using React, Vue, or mobile apps.

Unlike other JWT plugins that are bloated with settings screens and legacy support, ZenEyer Auth focuses on doing one thing perfectly: **Secure REST Authentication.**

**Why use this plugin?**

* **Zero Config:** Install it, activate it, and it works. Keys are generated automatically.
* **Opinionated Security:** Uses industry-standard HS256 encryption. No weak algorithm options.
* **Modern Standards:** Forces email-based login (better UX) and handles strict JSON responses.
* **Developer Friendly:** Clean code, namespaced PHP, and extensible hooks.

**API Endpoints:**

* `POST /wp-json/zeneyer/v1/auth/login` - Returns JWT + User Data
* `POST /wp-json/zeneyer/v1/auth/register` - Auto-login upon registration
* `POST /wp-json/zeneyer/v1/auth/validate` - Validates current token

== Installation ==

1. Upload the plugin folder to the `/wp-content/plugins/` directory.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. Done! Your API is now secured.

**Note for Headless Setup:**
Ensure your frontend application sends the token in the header:
`Authorization: Bearer <your-token>`

== Frequently Asked Questions ==

= How do I change the JWT Secret? =
The plugin automatically generates a strong secret in your database upon activation. For strict security, define `ZENEYER_JWT_SECRET` in your `wp-config.php` file.

= Can I change the token expiration time? =
By default, tokens last 7 days. You can modify the payload using the `zeneyer_auth_jwt_payload` filter.

== Changelog ==

= 1.0.0 =
* Initial release.
* Added Login, Register, and Validate endpoints.
* Implemented automatic secret generation.