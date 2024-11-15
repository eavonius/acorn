<?php

namespace Roots\Acorn\Http\Middleware;

use Closure;
use Illuminate\Support\Str;
use Illuminate\Http\Request;
use Illuminate\Routing\Route;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Contracts\Foundation\Application;
use Symfony\Component\HttpFoundation\Response;

/**
 * Intercepts HTTP requests and uses Wordpress to
 * render content if not matched by a Laravel route.
 */
class RequestInterception
{
    /**
     * Creates an instance of the middleware.
     *
     * @param Application app The laravel application object.
     * @param Kernel kernel The laravel application kernel.
     */
    public function __construct(
        private readonly Application $app,
        private readonly Kernel $kernel
    ) {
    }

    /**
     * Handle an incoming request.
     *
     * @param  Request $request The laravel request object.
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response) $next
     * @return mixed The result of the middleware invocation.
     */
    public function handle(Request $request, Closure $next): Response
    {
        $route = $request->route;
        $path = $request->getBaseUrl() . $request->getPathInfo();

        if ($this->isExcludedWordpressUrl($path)) {
            $response = $next($request);
            return $response;
        }

        $this->applyAcornRouterFilters($route);

        /** @var \Symfony\Component\HttpFoundation\Response $response */
        $response = $next($request);

        // When the router doesn't match the request, use Wordpress to handle it
        if ($response->isNotFound()) {
            $this->redirectIfCanonicalUrlExists();
            $this->applyConfiguredMiddleware($route, $path);

            ob_start();

            remove_action('shutdown', 'wp_ob_end_flush_all', 1);
            add_action('shutdown', fn () => $this->handleWordpressRequest($response), 100);
        } else {
            // The router matched the request, it's for Laravel (not Wordpress)
            add_action('wp_body_open', fn () => $this->handleRequest($response));
        }

        return $response;
    }

    /**
     * Checks whether the requested URL is excluded due to special usage by Wordpress.
     *
     * @param string path The path to check for exclusion.
     * @return boolean Whether to exclude continued middleware processing of the URL.
     */
    private function isExcludedWordpressUrl(string $path)
    {
        $except = collect([
            admin_url(),
            wp_login_url(),
            wp_registration_url(),
        ])->map(fn ($url) => parse_url($url, PHP_URL_PATH))->unique()->filter();

        return Str::startsWith($path, $except->all()) || Str::endsWith($path, '.php');
    }

    /**
     * Applies the acorn/router/do_parse_request filter if defined by a Wordpress theme.
     *
     * @param \Illuminate\Routing\Route|null route The route associated with the request or null if not matched.
     */
    private function applyAcornRouterFilters(?Route $route)
    {
        add_filter('do_parse_request', function ($condition, $wp, $params) use ($route) {
            if (!$route) {
                return $condition;
            }

            return apply_filters('acorn/router/do_parse_request', $condition, $wp, $params);
        }, 100, 3);
    }

    /**
     * Applies middleware to the URL appropriate to web or API endpoints in the routing config.
     *
     * @param \Illuminate\Routing\Route|null route The route associated with the request or null if not matched.
     * @param string path The absolute path to the requested URL or file.
     */
    private function applyConfiguredMiddleware(?Route $route, string $path)
    {
        if ($route != null) {
            $api = parse_url(rest_url(), PHP_URL_PATH);

            $middleware = Str::startsWith($path, $api)
                ? $this->app->config->get('router.wordpress.api', 'api')
                : $this->app->config->get('router.wordpress.web', 'web');

            $route->middleware($middleware);
        }
    }

    /**
     * Redirects to the canonical URL for a request if one exists.
     */
    private function redirectIfCanonicalUrlExists()
    {
        $canonicalUrl = redirect_canonical(null, false);

        if ($canonicalUrl) {
            wp_redirect($canonicalUrl);
            exit;
        }
    }

    /**
     * Called to attempt handling a URL request via Wordpress.
     *
     * @param Symfony\Component\HttpFoundation\Response response The HTTP response object.
     */
    private function handleWordpressRequest(Response $response)
    {
        foreach (headers_list() as $header) {
            [$header, $value] = explode(': ', $header, 2);

            if (! headers_sent()) {
                header_remove($header);
            }

            $response->headers->set($header, $value, $header !== 'Set-Cookie');
        }

        if ($this->app->hasDebugModeEnabled()) {
            $response->headers->set('X-Powered-By', $this->app->version());
        }

        $response->setStatusCode(http_response_code());

        $content = '';

        $levels = ob_get_level();

        for ($i = 0; $i < $levels; $i++) {
            $content .= ob_get_clean();
        }

        $response->setContent($content);

        $this->handleRequest($response);
    }

    /**
     * Called at the end of any request.
     *
     * @param Symfony\Component\HttpFoundation\Response response
     *  The HTTP response object.
     */
    private function handleRequest(Response $response)
    {
        $request = $this->app->request;

        $response->send();

        $this->kernel->terminate($request, $response);

        exit((int) $response->isServerError());
    }
}
