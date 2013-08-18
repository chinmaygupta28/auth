<?php namespace k\Auth;

use Illuminate\Support\ServiceProvider as IlluminateServiceProvider;

class ServiceProvider extends IlluminateServiceProvider {

	protected function registerConfig()
	{
		$this->app['auth.config'] = $this->app->share(function ($app) {
			return new Config($app['config']['auth']);
		});
	}

	protected function registerIdentityStore()
	{
		$this->app['auth.identity-store'] = $this->app->share(function ($app) {
			return new IdentityStore($app['auth.config'], $app['cache']->driver());
		});
	}

	protected function registerScope()
	{
		$this->app['auth.scope'] = $this->app->share(function ($app) {
			return new Scope;
		});
	}

	protected function registerHttpClient()
	{
		$this->app['auth.http-client'] = $this->app->share(function ($app) {
			return new HttpClient\Guzzle($app['auth.config'], $app->make('Guzzle\Http\Client'));
		});
	}

	protected function registerManager()
	{
		$this->app['auth'] = $this->app->share(function ($app) {
			return new Manager(
				$app['auth.config'], $app['auth.identity-store'],
				$app['auth.scope'], $app['auth.http-client'], $app['session']
			);
		});
	}

	public function register()
	{
		$this->registerConfig();
		$this->registerIdentityStore();
		$this->registerScope();
		$this->registerHttpClient();
		$this->registerManager();
	}

}