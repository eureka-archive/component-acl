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
 */
class AclResource
{
    /**
     * @var Resource $ascendant Ascendant resource class instance
     */
    protected $ascendant = null;

    /**
     * @var string $name Resource name.
     */
    protected $name = '';

    /**
     * @var array $rights List of rights
     */
    protected $rights = array();

    /**
     * @var array $roles List of roles
     */
    protected $roles = array();

    /**
     * Class constructor.
     *
     * @param string   $name
     * @param Resource $ascendant
     */
    public function __construct($name, $ascendant = null)
    {
        $this->name = $name;

        if ($ascendant instanceof AclResource) {
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
     * @return Resource|null
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

        if ($this->ascendant instanceof AclResource) {
            $ascendants = array_merge(array($this->ascendant->getName() => $this->ascendant), $this->ascendant->getAscendants());
        }

        return $ascendants;
    }

    /**
     * Set ascendant resource object.
     *
     * @param AclResource $ascendant
     * @return self
     */
    public function extend(AclResource $ascendant)
    {
        $this->ascendant = $ascendant;

        return $this;
    }

    /**
     * Allow specified role name with rights to current resource.
     *
     * @param string $role
     * @param array  $rights Bitmask rights array
     * @return self
     */
    public function allow($role, $rights)
    {
        $rights = !is_array($rights) ? array($rights) : $rights;

        if (!isset($this->rights[$role])) {
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
     * @param array  $rights Bitmask rights array
     * @return self
     */
    public function deny($role, $rights)
    {
        $rights = !is_array($rights) ? array($rights) : $rights;

        if (!isset($this->rights[$role])) {
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

        if ($this->ascendant instanceof AclResource) {
            $rights = $this->ascendant->compile($role);
        }

        //~ Compile ascendants rights & add current role at end
        $roles                   = $role->getAscendants();
        $roles[$role->getName()] = $role;

        foreach ($roles as $roleNameAscendant => $roleAscendant) {
            if (!isset($this->rights[$roleNameAscendant])) {
                continue;
            }

            foreach ($this->rights[$roleNameAscendant] as $right => $isAllowed) {
                if ($isAllowed) {
                    $rights = $rights | $right;
                } else {
                    $rights = $rights & (~$right);
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