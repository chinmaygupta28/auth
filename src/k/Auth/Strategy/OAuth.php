<?php namespace k\Auth\Strategy;

use Illuminate\Http\Request;
use k\Auth\Scope;
use k\Auth\Config;
use k\Auth\Contracts\HttpClientInterface as HttpClient;

class OAuth {

	protected static $booted = false;
	protected static $hardCodedDriversCache = [];

	protected $drivers = [];
	protected $customCreators = [];

	protected $config;
	protected $userRepository;
	protected $httpClient;
	protected $scope;

	public function __construct(Config $config, $userRepository, HttpClient $httpClient, Scope $scope)
	{
		$this->config = $config;
		$this->userRepository = $userRepository;
		$this->httpClient = $httpClient;
		$this->scope = $scope;
		
		if(! static::$booted)
		{
			static::boot();
			static::$booted = false;
		}
	}

	public static function boot()
	{
		$class = get_called_class();

		static::$hardCodedDriversCache[$class] = [];

		foreach (get_class_methods($class) as $method)
		{
			if(preg_match('/^create(.+)Driver$/', $method, $matches))
			{
				static::$hardCodedDriversCache[$class][] = snake_case($matches[1]);
			}
		}
	}

	protected function hardCodedDrivers()
	{
		return static::$hardCodedDriversCache[get_class($this)];
	}

	public function supportedProviders()
	{
		return array_unique(array_merge(array_keys($this->customCreators), $this->hardCodedDrivers()));
	}

	public function authenticate(Request $req)
	{
		$provider = $req->get($this->config->getOAuthProviderField());
		$token    = $req->get($this->config->getOAuthTokenField());

		if(in_array($provider, $this->supportedProviders()))
		{
			return $this->driver($provider)->authenticate($token);
		}

		return false;
	}

	public function register(Request $req)
	{
		$provider = $req->get($this->config->getOAuthProviderField());
		$token    = $req->get($this->config->getOAuthTokenField());

		if(in_array($provider, $this->supportedProviders()))
		{
			return $this->driver($provider)->register($token);
		}

		return false;
	}

	public function driver($driver)
	{
		if ( ! isset($this->drivers[$driver]))
		{
			$this->drivers[$driver] = $this->createDriver($driver);
		}

		return $this->drivers[$driver];
	}

	protected function createDriver($driver)
	{
		$method = 'create'.ucfirst($driver).'Driver';

		if (isset($this->customCreators[$driver]))
		{
			return $this->callCustomCreator($driver);
		}
		elseif (method_exists($this, $method))
		{
			return $this->$method();
		}

		throw new \InvalidArgumentException("Driver [$driver] not supported.");
	}

	protected function callCustomCreator($driver)
	{
		return $this->customCreators[$driver]($this);
	}

	////////////////

	protected function createFacebookDriver()
	{
		return new OAuth\Facebook($this->config, $this->userRepository, $this->httpClient, $this->scope);
	}

}