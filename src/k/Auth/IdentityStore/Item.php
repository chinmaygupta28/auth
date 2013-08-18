<?php namespace k\Auth\IdentityStore;

class Item {

	protected $identity;
	protected $usageCount;

	public function __construct($identity, $usageCount = 0)
	{
		$this->identity = $identity;
		$this->usageCount = (int) $usageCount;
	}

	public function getIdentity()
	{
		return $this->identity;
	}

	public function getUsageCount()
	{
		return $this->usageCount;
	}

	public function setIdentity($identity)
	{
		$this->identity = $identity;
		return $this;
	}

	public function setUsageCount($usageCount)
	{
		$this->usageCount = (int) $usageCount;
		return $this;
	}

	public function incrementUsageCount()
	{
		$this->usageCount = (int) $this->usageCount + 1;
		return $this;
	}

}