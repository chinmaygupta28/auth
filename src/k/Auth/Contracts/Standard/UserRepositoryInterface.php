<?php namespace k\Auth\Contracts\Standard;

use k\Auth\Contracts\UserRepositoryInterface as BaseUserRepositoryInterface;

interface UserRepositoryInterface extends BaseUserRepositoryInterface {

	public function findByUserCredentials($credentials);
}