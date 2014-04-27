<?php namespace k\Auth;

class Identity {

	protected $value;
	protected $usageCount;

	public function __construct($value, $usageCount = 0)
	{
		$this->value = $value;
		$this->usageCount = (int) $usageCount;
	}

	public function getValue()
	{
		return $this->value;
	}

	public function getUsageCount()
	{
		return $this->usageCount;
	}

	public function setValue($value)
	{
		$this->value = $value;
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