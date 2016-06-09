<?php

/**
 * Copyright (c) 2010-2016 Romain Cottard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Eureka\Component\Acl;

/**
 * Access Control Lists class.
 *
 * @author Romain Cottard
 * @version 2.1.0
 */
class Acl
{

    /**
     * List of Acl Resources
     *
     * @var array $resources
     */
    protected $resources = array();

    /**
     * List of Acl Rights
     *
     * @var array $rights
     */
    protected $rights = array();

    /**
     * List of Acl Roles
     *
     * @var array $roles
     */
    protected $roles = array();

    /**
     * Set true when acl is compiled
     *
     * @var boolean $isCompiled
     */
    protected $isCompiled = false;

    /**
     * Class constructor.
     *
     * @return Acl Current class instance.
     */
    public function __construct()
    {}

    /**
     * Compile acl data into a simplified array.
     *
     * @return Acl Current class instance.
     */
    protected function compile()
    {
        foreach ($this->resources as $resource => $resource) {
            foreach ($this->roles as $role => $role) {
                $this->rights[$role][$resource] = $resource->compile($role);
            }
        }

        $this->isCompiled = true;

        return $this;
    }

    /**
     * Reset Acl data
     *
     * @param boolean $isFull If we reset full data.
     * @return Acl Current class instance.
     */
    public function reset($isFull = true)
    {
        $this->roles = array();
        $this->resources = array();

        if ($isFull) {
            $this->isCompiled = false;
            $this->rights = array();
        }

        return $this;
    }

    /**
     * Clear all rights are not used by current role.
     *
     * @return Acl Current class instance
     */
    public function clearNotUsed($role)
    {
        if (! isset($this->rights[$role])) {
            throw new \Exception(__METHOD__ . '|Role is not defined in current ACL (role: ' . $role . ')');
        }

        //~ Keep current right
        $rights = $this->rights[$role];

        //~ Unset all rights / role
        unset($this->rights);
        unset($this->roles);

        //~ Re-Add only current rights / role
        $this->rights = array($role => $rights);
        $this->roles = array($role => true);

        return $this;
    }

    /**
     * Add new resource (by name) to acl.
     * We can specify ascendant resource.
     *
     * @param string|array $resources Resource name or list of resources name.
     * @param string $ascendant Ascendant resource name.
     * @return Acl Current class instance.
     * @throws \Exception
     */
    public function addResource($resources, $ascendant = '')
    {
        if (! is_array($resources)) {
            $resources = array($resources => (string) $ascendant);
        } else {
            $resources = $resources;
        }

        //~ Add specified resource(s) to internal list.
        foreach ($resources as $name => $ascendant) {
            $ascendant = null;

            if (isset($this->resources[$name])) {
                throw new \Exception(__METHOD__ . '|Resource with same name already exists ! (name: ' . htmlentities($name) . ')');
            }

            if (! empty($ascendant)) {
                if (! isset($this->resources[$ascendant])) {
                    throw new \Exception(__METHOD__ . '|Ascendant resource does not exists ! (ascendant name: ' . htmlentities($ascendant) . ')');
                }

                $ascendant = $this->resources[$ascendant];
            }

            $this->resources[$name] = new Resource($name, $ascendant);
        }

        return $this;
    }

    /**
     * Add new role (by name) to acl.
     * We can specify ascendant role.
     *
     * @param string|array $role Role name or list of role name.
     * @param string $ascendant Ascendant role name.
     * @return Acl Current class instance.
     * @throws \Exception
     */
    public function addRole($role, $ascendant = '')
    {
        if (! is_array($role)) {
            $roles = array($role => (string) $ascendant);
        } else {
            $roles = $role;
        }

        //~ Add specified role(s) to internal list.
        foreach ($roles as $name => $ascendant) {
            $ascendant = null;

            if (isset($this->roles[$name])) {
                throw new \Exception(__METHOD__ . '|Role with same name already exists !');
            }

            if (! empty($ascendant)) {
                if (! isset($this->roles[$ascendant])) {
                    throw new \Exception(__METHOD__ . '|Ascendant Role does not exists ! (ascendant name: ' . htmlentities($ascendant) . ')');
                }

                $ascendant = $this->roles[$ascendant];
            }

            $this->roles[$name] = new Role($name, $ascendant);
        }

        return $this;
    }

    /**
     * Allow one or more role for specified resource(s) with list of rights.
     * Reset compiled flag.
     *
     * @param array $roles
     * @param array $resources
     * @param array $rigt
     * @return Acl Current class instance.
     * @throws \Exception
     */
    public function allow($roles, $resources, $rights)
    {
        $this->isCompiled = false;

        $roles = (array) $roles;
        $resources = (array) $resources;
        $rights = (array) $rights;

        if (empty($roles)) {
            $roles = array_keys($this->roles);
        }

        if (empty($resources)) {
            $resources = array_keys($this->resources);
        }

        //~ For each resource, unset bad specifed resources.
        //~ Then, deny rights from resource and detach resource from each role.
        foreach ($resources as $resource) {
            if (! isset($this->resources[$resource])) {
                unset($resources[$resource]);
            }

            foreach ($roles as $role) {
                if (! isset($this->roles[$role])) {
                    throw new \Exception(__METHOD__ . '|Role does not exists ! (role: ' . htmlentities($role) . ')');
                }

                $this->resources[$resource]->allow($role, $rights);
            }
        }

        return $this;
    }

    /**
     * Deny one or more role for specified resource(s) with list of rights.
     * Reset compiled flag.
     *
     * @param array $roles
     * @param array $resources
     * @param array $rigt
     * @return Acl Current class instance.
     * @throws \Exception
     */
    public function deny($roles, $resources, $rights)
    {
        $this->isCompiled = false;

        $roles = (array) $roles;
        $resources = (array) $resources;
        $rights = (array) $rights;

        if (empty($roles)) {
            $roles = array_keys($this->roles);
        }

        if (empty($resources)) {
            $resources = array_keys($this->resources);
        }

        //~ For each resource, unset bad specifed resources.
        //~ Then, deny rights from resource and detach resource from each role.
        foreach ($resources as $resource) {
            if (! isset($this->resources[$resource])) {
                unset($resources[$resource]);
            }

            foreach ($roles as $role) {
                if (! isset($this->roles[$role])) {
                    throw new \Exception(__METHOD__ . '|Role does not exists ! (role: ' . htmlentities($role) . ')');
                }

                $this->resources[$resource]->deny($role, $rights);
            }
        }

        return $this;
    }

    /**
     * Verify if role has right(s) for specified resource.
     *
     * @param string $role
     * @param string $resource
     * @param integer $rights Bitmask rights
     * @return boolean
     * @throws \Exception
     */
    public function isAllowed($role, $resource, $rights)
    {
        if (! isset($this->roles[$role])) {
            throw new \Exception(__METHOD__ . '|Role specified does not exists !');
        }

        if (! $this->isCompiled) {
            $this->compile();
        }

        if (! isset($this->rights[$role][$resource])) {
            return Right::NO_RIGHTS;
        }

        return ($rights === ($this->rights[$role][$resource] & $rights));
    }
}