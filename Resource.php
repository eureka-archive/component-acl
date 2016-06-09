<?php

/**
 * Copyright (c) 2010-2016 Romain Cottard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Eureka\Component\Acl;

/**
 * Access Control Lists Resource.
 *
 * @author Romain Cottard
 * @version 2.1.0
 */
class Resource
{

    /**
     * Ascendant resource class instance
     *
     * @var Eureka\Component\Acl\Resource $ascendant
     */
    protected $ascendant = null;

    /**
     * Resource name.
     *
     * @var string $name
     */
    protected $name = '';

    /**
     * List of rights
     *
     * @var array $rights
     */
    protected $rights = array();

    /**
     * List of roles
     *
     * @var array $roles
     */
    protected $roles = array();

    /**
     * Class constructor.
     *
     * @param string $name
     * @param Eureka\Component\Acl\Resource $ascendant
     * @return Eureka\Component\Acl\Resource Current class instance
     */
    public function __construct($name, $ascendant = null)
    {
        $this->name = $name;

        if ($ascendant instanceof Resource) {
            $this->extend($ascendant);
        }
    }

    /**
     * Get resource name.
     *
     * @return string
     */
    public function getName()
    {
        return $this->name;
    }

    /**
     * Get ascendant resource object
     *
     * @return null|Eureka\Component\Acl\Resource
     */
    public function getAscendant()
    {
        return $this->ascendant;
    }

    /**
     * Get all ascendants resources
     *
     * @return array
     */
    public function getAscendants()
    {
        $ascendants = array();

        if ($this->ascendant instanceof Resource) {
            $ascendants = array_merge(array($this->ascendant->getName() => $this->ascendant), $this->ascendant->getAscendants());
        }

        return $ascendants;
    }

    /**
     * Set ascendant resource object.
     *
     * @param Resource $ascendant
     * @return Resource Current class instance.
     */
    public function extend(Resource $ascendant)
    {
        $this->ascendant = $ascendant;

        return $this;
    }

    /**
     * Allow specified role name with rights to current resource.
     *
     * @param string $role
     * @param array $rights Bitmask rights array
     * @return Resource Current class instance.
     */
    public function allow($role, $rights)
    {
        $rights = ! is_array($rights) ? array($rights) : $rights;

        if (! isset($this->rights[$role])) {
            $this->rights[$role] = array();
        }

        foreach ($rights as $right) {
            $this->rights[$role][$right] = true;
        }

        return $this;
    }

    /**
     * Deny specified role name with rights to current resource.
     *
     * @param string $role
     * @param array $rights Bitmask rights array
     * @return Resource Current class instance.
     */
    public function deny($role, $rights)
    {
        if (! isset($this->rights[$role])) {
            $this->rights[$role] = array();
        }

        foreach ($rights as $right) {
            $this->rights[$role][$right] = false;
        }

        return $this;
    }

    /**
     * Compiled resource data into unique bitmask value.
     * Rights compilation order: Compile Resources AND AFTER Roles. Role have final word !
     *
     * @param Role $role
     * @return integer Bitmask compiled right value.
     */
    public function compile(Role $role)
    {
        $rights = Right::NO_RIGHTS;

        if ($this->ascendant instanceof Resource) {
            $rights = $this->ascendant->compile($role);
        }

        //~ Compile ascendants rights & add current role at end
        $roles = $role->getAscendants();
        $roles[$role->getName()] = $role;

        foreach ($roles as $roleAscendant => $roleAscendant) {
            if (! isset($this->rights[$roleAscendant])) {
                continue;
            }

            foreach ($this->rights[$roleAscendant] as $right => $isAllowed) {
                if ($isAllowed) {
                    $rights = $rights | $right;
                } else {
                    $rights = $rights & (~ $right);
                }
            }
        }

        return $rights;
    }

    /**
     * Helper method.
     * Return value for all resources.
     *
     * @return array()
     */
    public static function all()
    {
        return array();
    }
}