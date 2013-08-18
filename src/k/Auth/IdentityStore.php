<?php namespace k\Auth;

use k\Auth\IdentityStore\Item;
use Illuminate\Cache\Repository;

class IdentityStore {

	protected $config;
	protected $repository;

	public function __construct(Config $config, Repository $repository)
	{
		$this->config = $config;
		$this->repository = $repository;
	}

	protected function getExpiryTime()
	{
		return $this->config->getApiKeyLifetime();
	}

	public function get($key)
	{
		return $this->repository->get($key);
	}

	public function put($key, Item $value)
	{
		$time = $this->getExpiryTime();

		$this->repository->put($key, $value, $time);
		return $this;
	}

	public function putIdentity($key, $identity)
	{
		if($item = $this->get($key))
		{
			$item->setIdentity($identity);
			return $this->put($key, $item);
		}
		else
		{
			return $this->put($key, new Item($identity));
		}
	}

	public function getIdentity($key)
	{
		if($item = $this->get($key))
		{
			return $item->getIdentity();
		}
		else
		{
			return null;
		}
	}

	public function putUsageCount($key, $count)
	{
		$count = (int) $count;

		if($item = $this->get($key))
		{
			$item->setUsageCount($count);
			return $this->put($key, $item);
		}

		return $this;
	}

	public function incrementUsageCount($key)
	{
		if($item = $this->get($key))
		{
			$item->incrementUsageCount();
			return $this->put($key, $item);
		}

		return $this;
	}

	public function forget($key)
	{
		$this->repository->forget($key);
		return $this;
	}

	public function refresh($key)
	{
		$refreshedKey = $this->generateRandomKey();

		if($item = $this->get($key))
		{
			$item->setUsageCount(0);

			$this->forget($key)
				 ->put($refreshedKey, $item);
		}

		return $refreshedKey;
	}

	public function generateRandomKey()
	{
		return hash('sha512', uniqid(get_class($this), true));
	}

}