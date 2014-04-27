<?php namespace k\Auth;

class Scope {

	protected $data = [];

	protected function setAttr($attr, $val)
	{
		$this->data[$attr] = $val;
		return $this;
	}

	protected function getAttr($attr)
	{
		return isset($this->data[$attr]) ? $this->data[$attr] : null;
	}

	public function clear()
	{
		$this->data = [];
		return $this;
	}

	public function __call($method, $params)
	{
		if(strpos($method, 'set') === 0)
		{
			$attr = lcfirst(substr($method, 3));
			return $this->setAttr($attr, reset($params));
		}

		if(strpos($method, 'get') === 0)
		{
			$attr = lcfirst(substr($method, 3));
			return $this->getAttr($attr);
		}

		throw new \BadMethodCallException(get_class($this).'::'.$method);
	}

}