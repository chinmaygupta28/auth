<?php namespace k\Auth;

use Illuminate\Support\Facades\Facade as IlluminateFacade;

class Facade extends IlluminateFacade {

	protected static function getFacadeAccessor()
	{
		return 'auth';
	}

	public static function scope()
	{
		return static::getScope();
	}

	public static function config()
	{
		return static::getConfig();
	}

}