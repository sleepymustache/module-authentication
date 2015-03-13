# Authentication Module

## Overview
This module create a basic authentication structure. It provides 4 tables: Users, UserMeta, Roles, and Permissions. Each user is assigned a Role and each role consists of permissions. The UserMeta table is used to store key/value pairs associated with a User. This allows any amount of data to be associated with Users.

## Getting Started
To get started with the User class. You must first run the sql script included. This script will setup the necessary database structure. 

## Role class

### Role Creation

	try {
		$r = new \Module\Authentication\Role();
		$r->columns['name']    = "Editor";
		$r->save();
	} catch (\Exception $e) {
		echo $e->getMessage();
	}

### Adding permissions to a role

	try {
		$r = new \Module\Authentication\Role();
		$r->load(2); // The editor role for example
		$r->setPermission('edit-articles', true);
		$r->save();
	} catch (\Exception $e) {
		echo $e->getMessage();
	}

## User Class

### User Creation

	try {
		$u = new \Module\Authentication\User();
		$u->columns['email']    = "user@domain.com";
		$u->columns['password'] = $u->saltPassword('test');
		$u->columns['role_id']  = 1; // 1 is the default Admin role
		$u->save();
	} catch (\Exception $e) {
		echo $e->getMessage();
	}

### Adding additional data to a user

	try {
		$u = new \Module\Authentication\User();
		$u->load(1); // Load user with ID 1
		$u->setUserData('title', 'Web Developer');
		$u->setUserData('salary', 200000);
	} catch (\Exception $e) {
		echo $e->getMessage();
	}

### Getting additional data for a user

	try {
		$u = new \Module\Authentication\User();
		$u->load(1); // Load user with ID 1
		$title = $u->getUserData('title');
		$salary = $u->getUserData('salary');
	} catch (\Exception $e) {
		echo $e->getMessage();
	}

### Authentication

	try {
		$u = new \Module\Authentication\User();
		$_SESSION['uid'] = $u->authenticate('user@domain.com', 'test');
		echo "Authentication successful. User ID is ", $_SESSION['uid'];
	} catch (\Exception $e) {
		echo $e->getMessage();
	}

### Check for permissions

	try {
		$u = new \Module\Authentication\User();
		$u->load(1); // Load user with ID 1
		if ($u->hasPermission('delete-user')) {
			$u->delete();
		} else {
			throw \Exception('User does not have correct permissions');
		}
	} catch (\Exception $e) {
		echo $e->getMessage();
	}