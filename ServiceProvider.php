<?php namespace k\Auth;

use Illuminate\Support\ServiceProvider as IlluminateServiceProvider;
use Guzzle;

class ServiceProvider extends IlluminateServiceProvider {

	protected function registerConfig()
	{
		$this->app['auth.config'] = $this->app->share(function ($app) {
			return new Config($app['config']['auth']);
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
			return new HttpClient\Guzzle($app['auth.config'], new Guzzle\Http\Client);
		});
	}

	protected function registerManager()
	{
		$this->app['auth'] = $this->app->share(function ($app) {
			return new Manager(
				$app['auth.config'], $app['auth.scope'], $app['auth.http-client'], $app['session.store']
			);
		});
	}

	public function register()
	{
		$this->registerConfig();
		$this->registerScope();
		$this->registerHttpClient();
		$this->registerManager();
	}

}