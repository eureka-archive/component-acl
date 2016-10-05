<?php

/**
 * Copyright (c) 2010-2016 Romain Cottard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Eureka\Component\Acl;

/**
 * Access Control Lists Role.
 *
 * @author Romain Cottard
 * @version 1.0.0
 */
class Role
{
    /**
     * Ascendant role object
     *
     * @var null|Role $ascendant
     */
    protected $ascendant = null;

    /**
     * Role name
     *
     * @var string $name
     */
    protected $name = null;

    /**
     * Class constructor.
     *
     * @param string $name Role name.
     * @param null|Role $ascendant Ascendant role
     */
    public function __construct($name, $ascendant = null)
    {
        $this->name = $name;

        if ($ascendant instanceof Role) {
            $this->extend($ascendant);
        }
    }

    /**
     * Get role name.
     *
     * @return string
     */
    public function getName()
    {
        return $this->name;
    }

    /**
     * Get ascendant role object.
     *
     * @return null|Role
     */
    public function getAscendant()
    {
        return $this->ascendant;
    }

    /**
     * Get list of ascendant roles
     *
     * @return array List of ascendant roles.
     */
    public function getAscendants()
    {
        $ascendants = array();

        if ($this->ascendant instanceof Role) {
            $ascendants = array_merge($this->ascendant->getAscendants() + array($this->ascendant->getName() => $this->ascendant));
        }

        return $ascendants;
    }

    /**
     * Set ascendant role.
     *
     * @param Role $ascendant
     * @return Role Current class instance
     */
    public function extend(Role $ascendant)
    {
        $this->ascendant = $ascendant;

        return $this;
    }

    /**
     * Helper method.
     * Return value for all roles (empty array).
     *
     * @return array
     */
    public static function all()
    {
        return array();
    }
}