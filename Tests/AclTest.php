<?php

/**
 * Copyright (c) 2010-2016 Romain Cottard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Eureka\Component\Acl;

require_once __DIR__ . '/../Acl.php';
require_once __DIR__ . '/../Resource.php';
require_once __DIR__ . '/../Role.php';
require_once __DIR__ . '/../Right.php';

/**
 * Access Control Lists Role.
 *
 * @author Romain Cottard
 * @version 2.1.0
 */
class AclTest extends \PHPUnit_Framework_TestCase
{
    /**
     * Init resources & roles
     *
     * @return Acl
     * @covers Acl::__construct
     * @covers Acl::addResource
     * @covers Acl::addRole
     * @covers Acl::reset
     */
    public function init()
    {
        // Roles:     root => admin => dev, edito, guest
        // Resources: home, catalog => import|album => track
        // Rights:    create, read, update, delete

        $acl = new Acl();
        $acl->reset();
        $acl->addResource('home');
        $acl->addResource(array('catalog' => '', 'import' => 'catalog', 'album' => 'catalog', 'track' => 'album'));

        $acl->addRole('root');
        $acl->addRole(array('admin' => 'root', 'dev' => 'admin', 'edito' => 'admin', 'guest' => ''));

        return $acl;
    }

    /**
     * Simple test: root role with all rights for all resources
     *
     * @return void
     * @covers Acl::allow
     */
    public function testRoot()
    {
        $acl = $this->init();

        $acl->allow('root', Resource::all(), Right::all());

        $test = '
          ||     home      ||    catalog    ||    import     ||     album     ||     track     ||
          || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D ||
 | root   || x | x | x | x || x | x | x | x || x | x | x | x || x | x | x | x || x | x | x | x ||
 | admin  || x | x | x | x || x | x | x | x || x | x | x | x || x | x | x | x || x | x | x | x ||
 | dev    || x | x | x | x || x | x | x | x || x | x | x | x || x | x | x | x || x | x | x | x ||
 | edito  || x | x | x | x || x | x | x | x || x | x | x | x || x | x | x | x || x | x | x | x ||
 | guest  || - | - | - | - || - | - | - | - || - | - | - | - || - | - | - | - || - | - | - | - ||
';
        $this->assertEquals($this->getTableRights($acl), $test);
    }

    /**
     * Test more acl
     *
     * @return void
     */
    public function testAclMore()
    {
        //~ Create new instance object of acl class
        $acl = new Acl();

        //~ Add resources (for example, page in BO)
        //~ Single resource, no ascendant
        $acl->addResource('home');
        //~ Add multiple resources, some with ascendant
        $acl->addResource(array('catalog' => '', 'import' => 'catalog', 'album' => 'catalog'));

        //~ Add roles (group & user)
        //~ Single role
        $acl->addRole('admin');
        //~ Add multiple roles, some with ascendant
        $acl->addRole(array('guest' => '', 'dev' => '', 'edito' => '', 'rco' => 'dev'));
        //~ Add single role with ascendant
        $acl->addRole('vk', 'dev');

        //~ For 'admin' role, allow all rights for all resources.
        $acl->allow('admin', Resource::all(), Right::all());

        //~ For 'guest' role deny all rights for all resources.
        $acl->deny('guest', Resource::all(), Right::all());

        //~ For 'dev' & 'edito' role allow all rights for all resources.
        $acl->allow(array('dev', 'edito'), array('home', 'catalog'), Right::all());
        $acl->deny(array('dev', 'edito'), Resource::all(), Right::get('delete'));
        $acl->deny('edito', 'catalog', Right::all());
        $acl->deny('dev', 'import', array(Right::get('create'), Right::get('update')));

        //~ For 'rco' role, allow 'delete' on 'catalog' resources
        $acl->allow('rco', 'import', Right::all());

        //~ Now, display an representation of this data in a table, with the inheritances.
        //          ||     home      ||    catalog    ||    import     ||     album     ||
        //          || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D ||
        // | admin  || x | x | x | x || x | x | x | x || x | x | x | x || x | x | x | x ||
        // | dev    || x | x | x | o || x | x | x | o || o | S | o | o || S | S | S | o ||
        // | edito  || x | x | x | o || o | o | o | o || r | s | r | o || s | s | s | o ||
        // | rco    || R | R | R | r || R | R | R | r || x | x | x | x || S | S | S | r ||
        // | vk     || R | R | R | r || R | R | R | r || r | S | r | r || S | S | S | r ||
        // | guest  || o | o | o | o || o | o | o | o || o | o | o | o || o | o | o | o ||

        $test = '
          ||     home      ||    catalog    ||    import     ||     album     ||
          || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D ||
 | admin  || x | x | x | x || x | x | x | x || x | x | x | x || x | x | x | x ||
 | dev    || x | x | x | - || x | x | x | - || - | x | - | - || x | x | x | - ||
 | edito  || x | x | x | - || - | - | - | - || - | - | - | - || - | - | - | - ||
 | rco    || x | x | x | - || x | x | x | - || x | x | x | x || x | x | x | - ||
 | vk     || x | x | x | - || x | x | x | - || - | x | - | - || x | x | x | - ||
 | guest  || - | - | - | - || - | - | - | - || - | - | - | - || - | - | - | - ||
';
        $this->assertEquals($this->getTableRights($acl, array(
            'admin', 'dev', 'edito', 'rco', 'vk', 'guest',
        ), array('home', 'catalog', 'import', 'album')), $test);
    }

    /**
     * More testing about Acl classes.
     *
     * @return void
     * @covers Acl::__construct
     * @covers Acl::allow
     * @covers Acl::deny
     * @covers Resuorce::all
     * @covers Right::all
     */
    public function testAcl()
    {
        $acl = $this->init();

        $acl->allow('root', Resource::all(), Right::all());
        $acl->deny('guest', Resource::all(), Right::all());

        $acl->deny('admin', Resource::all(), Right::get('delete'));
        $acl->deny(array('dev', 'edito'), Resource::all(), array(Right::get('create'), Right::get('update')));
        $acl->allow('dev', 'import', Right::all());

        $acl->allow('edito', 'album', array(Right::get('create'), Right::get('update'), Right::get('read')));
        $acl->allow('edito', 'catalog', Right::get('delete'));
        /* R: Herit allow from Role, r: Herit deny from Role, S: Herit from Resource, s: Herit deny from Resource, o: Deny, -: No rights
                  ||      home     ||   catalog     ||    import     ||    album      ||    track      ||
                  || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D ||
         | root   || x | x | x | x || x | x | x | x || x | x | x | x || x | x | x | x || x | x | x | x ||
         | admin  || R | R | R | o || R | R | R | o || R | R | R | o || R | R | R | o || R | R | R | o ||
         | dev    || o | R | o | r || o | R | o | r || x | x | x | x || o | R | o | r || o | R | o | r ||
         | edito  || o | R | o | r || o | R | o | x || o | R | o | r || x | x | x | r || o | R | o | r ||
         | guest  || o | o | o | o || o | o | o | o || o | o | o | o || o | o | o | o || o | o | o | o ||
        */
        $test = '
          ||     home      ||    catalog    ||    import     ||     album     ||     track     ||
          || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D ||
 | root   || x | x | x | x || x | x | x | x || x | x | x | x || x | x | x | x || x | x | x | x ||
 | admin  || x | x | x | - || x | x | x | - || x | x | x | - || x | x | x | - || x | x | x | - ||
 | dev    || - | x | - | - || - | x | - | - || x | x | x | x || - | x | - | - || - | x | - | - ||
 | edito  || - | x | - | - || - | x | - | x || - | x | - | - || x | x | x | - || - | x | - | - ||
 | guest  || - | - | - | - || - | - | - | - || - | - | - | - || - | - | - | - || - | - | - | - ||
';

        $this->assertEquals($this->getTableRights($acl), $test);
    }

    /**
     * Test allow
     *
     * @return void
     * @covers Acl::allow
     * @covers Role::all
     * @covers Right::get
     */
    public function testAllow()
    {
        $acl = $this->init();

        //--------------------------------------------------------
        //  Role: ALL, Resource: catalog, Rights: read
        //--------------------------------------------------------
        $acl->allow(Role::all(), 'catalog', Right::get('read'));
        /* R: Herit allow from Role, r: Herit deny from Role, S: Herit from Resource, s: Herit deny from Resource, o: Deny, -: No rights
                  ||      home     ||   catalog     ||    import     ||    album      ||    track      ||
                  || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D ||
         | root   || - | - | - | - || - | x | - | - || - | S | - | - || - | S | - | - || - | S | - | - ||
         | admin  || - | - | - | - || - | x | - | - || - | S | - | - || - | S | - | - || - | S | - | - ||
         | dev    || - | - | - | - || - | x | - | - || - | S | - | - || - | S | - | - || - | S | - | - ||
         | edito  || - | - | - | - || - | x | - | - || - | S | - | - || - | S | - | - || - | S | - | - ||
         | guest  || - | - | - | - || - | x | - | - || - | S | - | - || - | S | - | - || - | S | - | - ||
        */
        $test = '
          ||     home      ||    catalog    ||    import     ||     album     ||     track     ||
          || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D ||
 | root   || - | - | - | - || - | x | - | - || - | x | - | - || - | x | - | - || - | x | - | - ||
 | admin  || - | - | - | - || - | x | - | - || - | x | - | - || - | x | - | - || - | x | - | - ||
 | dev    || - | - | - | - || - | x | - | - || - | x | - | - || - | x | - | - || - | x | - | - ||
 | edito  || - | - | - | - || - | x | - | - || - | x | - | - || - | x | - | - || - | x | - | - ||
 | guest  || - | - | - | - || - | x | - | - || - | x | - | - || - | x | - | - || - | x | - | - ||
';
        $this->assertEquals($test, $this->getTableRights($acl));

        //--------------------------------------------------------
        //  Role: guest, Resource: ALL, Rights: ALL
        //--------------------------------------------------------
        $acl->allow('guest', Resource::all(), Right::all());
        /* R: Herit allow from Role, r: Herit deny from Role, S: Herit from Resource, s: Herit deny from Resource, o: Deny, -: No rights
                  ||      home     ||   catalog     ||    import     ||    album      ||    track      ||
                  || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D ||
         | root   || - | - | - | - || - | x | - | - || - | S | - | - || - | S | - | - || - | S | - | - ||
         | admin  || - | - | - | - || - | x | - | - || - | S | - | - || - | S | - | - || - | S | - | - ||
         | dev    || - | - | - | - || - | x | - | - || - | S | - | - || - | S | - | - || - | S | - | - ||
         | edito  || - | - | - | - || - | x | - | - || - | S | - | - || - | S | - | - || - | S | - | - ||
         | guest  || x | x | x | x || x | x | x | x || x | x | x | x || x | x | x | x || x | x | x | x ||
        */
        $test = '
          ||     home      ||    catalog    ||    import     ||     album     ||     track     ||
          || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D ||
 | root   || - | - | - | - || - | x | - | - || - | x | - | - || - | x | - | - || - | x | - | - ||
 | admin  || - | - | - | - || - | x | - | - || - | x | - | - || - | x | - | - || - | x | - | - ||
 | dev    || - | - | - | - || - | x | - | - || - | x | - | - || - | x | - | - || - | x | - | - ||
 | edito  || - | - | - | - || - | x | - | - || - | x | - | - || - | x | - | - || - | x | - | - ||
 | guest  || x | x | x | x || x | x | x | x || x | x | x | x || x | x | x | x || x | x | x | x ||
';
        $this->assertEquals($test, $this->getTableRights($acl));

        //--------------------------------------------------------
        //  Role: edito, Resource: ALL, Rights: read
        //--------------------------------------------------------
        $Acl->allow('edito', Resource::all(), Right::get('read'));
        /* R: Herit allow from Role, r: Herit deny from Role, S: Herit from Resource, s: Herit deny from Resource, o: Deny, -: No rights
                  ||      home     ||   catalog     ||    import     ||    album      ||    track      ||
                  || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D ||
         | root   || - | - | - | - || - | x | - | - || - | S | - | - || - | S | - | - || - | S | - | - ||
         | admin  || - | - | - | - || - | x | - | - || - | S | - | - || - | S | - | - || - | S | - | - ||
         | dev    || - | - | - | - || - | x | - | - || - | S | - | - || - | S | - | - || - | S | - | - ||
         | edito  || - | x | - | - || - | x | - | - || - | x | - | - || - | x | - | - || - | x | - | - ||
         | guest  || x | x | x | x || x | x | x | x || x | x | x | x || x | x | x | x || x | x | x | x ||
        */
        $test = '
          ||     home      ||    catalog    ||    import     ||     album     ||     track     ||
          || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D ||
 | root   || - | - | - | - || - | x | - | - || - | x | - | - || - | x | - | - || - | x | - | - ||
 | admin  || - | - | - | - || - | x | - | - || - | x | - | - || - | x | - | - || - | x | - | - ||
 | dev    || - | - | - | - || - | x | - | - || - | x | - | - || - | x | - | - || - | x | - | - ||
 | edito  || - | x | - | - || - | x | - | - || - | x | - | - || - | x | - | - || - | x | - | - ||
 | guest  || x | x | x | x || x | x | x | x || x | x | x | x || x | x | x | x || x | x | x | x ||
';
        $this->assertEquals($test, $this->getTableRights($acl));

        //--------------------------------------------------------
        //  Role: dev, Resource: import, Rights: create, delete
        //--------------------------------------------------------
        $acl->allow('admin', 'import', array(Right::get('create'), Right::get('delete')));
        /* R: Herit allow from Role, r: Herit deny from Role, S: Herit from Resource, s: Herit deny from Resource, o: Deny, -: No rights
                  ||      home     ||   catalog     ||    import     ||    album      ||    track      ||
                  || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D ||
         | root   || - | - | - | - || - | x | - | - || - | S | - | - || - | S | - | - || - | S | - | - ||
         | admin  || - | - | - | - || - | x | - | - || x | S | - | x || - | S | - | - || - | S | - | - ||
         | dev    || - | - | - | - || - | x | - | - || R | S | - | R || - | S | - | - || - | S | - | - ||
         | edito  || - | x | - | - || - | x | - | - || R | x | - | R || - | x | - | - || - | x | - | - ||
         | guest  || x | x | x | x || x | x | x | x || x | x | x | x || x | x | x | x || x | x | x | x ||
        */
        $test = '
          ||     home      ||    catalog    ||    import     ||     album     ||     track     ||
          || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D ||
 | root   || - | - | - | - || - | x | - | - || - | x | - | - || - | x | - | - || - | x | - | - ||
 | admin  || - | - | - | - || - | x | - | - || x | x | - | x || - | x | - | - || - | x | - | - ||
 | dev    || - | - | - | - || - | x | - | - || x | x | - | x || - | x | - | - || - | x | - | - ||
 | edito  || - | x | - | - || - | x | - | - || x | x | - | x || - | x | - | - || - | x | - | - ||
 | guest  || x | x | x | x || x | x | x | x || x | x | x | x || x | x | x | x || x | x | x | x ||
';
        $this->assertEquals($test, $this->getTableRights($acl));

        //--------------------------------------------------------
        //  Role: root, Resource: catalog, Rights: update
        //--------------------------------------------------------
        $acl->allow('root', 'album', Right::get('update'));
        /* R: Herit allow from Role, r: Herit deny from Role, S: Herit from Resource, s: Herit deny from Resource, o: Deny, -: No rights
                  ||      home     ||   catalog     ||    import     ||    album      ||    track      ||
                  || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D ||
         | root   || - | - | - | - || - | x | - | - || - | S | - | - || - | S | x | - || - | S | S | - ||
         | admin  || - | - | - | - || - | x | - | - || x | S | - | x || - | S | R | - || - | S | S | - ||
         | dev    || - | - | - | - || - | x | - | - || R | S | - | R || - | S | R | - || - | S | S | - ||
         | edito  || - | x | - | - || - | x | - | - || R | x | - | R || - | x | R | - || - | x | S | - ||
         | guest  || x | x | x | x || x | x | x | x || x | x | x | x || x | x | x | x || x | x | x | x ||
        */
        $test = '
          ||     home      ||    catalog    ||    import     ||     album     ||     track     ||
          || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D ||
 | root   || - | - | - | - || - | x | - | - || - | x | - | - || - | x | x | - || - | x | x | - ||
 | admin  || - | - | - | - || - | x | - | - || x | x | - | x || - | x | x | - || - | x | x | - ||
 | dev    || - | - | - | - || - | x | - | - || x | x | - | x || - | x | x | - || - | x | x | - ||
 | edito  || - | x | - | - || - | x | - | - || x | x | - | x || - | x | x | - || - | x | x | - ||
 | guest  || x | x | x | x || x | x | x | x || x | x | x | x || x | x | x | x || x | x | x | x ||
';
        $this->assertEquals($test, $this->getTableRights($acl));

        //--------------------------------------------------------
        //  Check previous rights
        //--------------------------------------------------------
        $test = '
          ||     home      ||    catalog    ||    import     ||     album     ||     track     ||
          || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D ||
 | root   || - | - | - | - || - | x | - | - || - | x | - | - || - | x | x | - || - | x | x | - ||
 | admin  || - | - | - | - || - | x | - | - || x | x | - | x || - | x | x | - || - | x | x | - ||
 | dev    || - | - | - | - || - | x | - | - || x | x | - | x || - | x | x | - || - | x | x | - ||
 | edito  || - | x | - | - || - | x | - | - || x | x | - | x || - | x | x | - || - | x | x | - ||
 | guest  || x | x | x | x || x | x | x | x || x | x | x | x || x | x | x | x || x | x | x | x ||
';
        $this->assertEquals($test, $this->getTableRights($acl));

        //--------------------------------------------------------
        //  Role: guest, Resource: track, Rights: update
        //--------------------------------------------------------
        $acl->deny(Role::all(), 'track', Right::get('update'));
        /* R: Herit allow from Role, r: Herit deny from Role, S: Herit from Resource, s: Herit deny from Resource, o: Deny, -: No rights
                  ||      home     ||   catalog     ||    import     ||    album      ||    track      ||
                  || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D ||
         | root   || - | - | - | - || - | x | - | - || - | S | - | - || - | S | x | - || - | S | o | - ||
         | admin  || - | - | - | - || - | x | - | - || x | S | - | x || - | S | R | - || - | S | o | - ||
         | dev    || - | - | - | - || - | x | - | - || R | S | - | R || - | S | R | - || - | S | o | - ||
         | edito  || - | x | - | - || - | x | - | - || R | x | - | R || - | x | R | - || - | x | o | - ||
         | guest  || x | x | x | x || x | x | x | x || x | x | x | x || x | x | x | x || x | x | o | x ||
        */
        $test = '
          ||     home      ||    catalog    ||    import     ||     album     ||     track     ||
          || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D ||
 | root   || - | - | - | - || - | x | - | - || - | x | - | - || - | x | x | - || - | x | - | - ||
 | admin  || - | - | - | - || - | x | - | - || x | x | - | x || - | x | x | - || - | x | - | - ||
 | dev    || - | - | - | - || - | x | - | - || x | x | - | x || - | x | x | - || - | x | - | - ||
 | edito  || - | x | - | - || - | x | - | - || x | x | - | x || - | x | x | - || - | x | - | - ||
 | guest  || x | x | x | x || x | x | x | x || x | x | x | x || x | x | x | x || x | x | - | x ||
';
        $this->assertEquals($test, $this->getTableRights($acl));

        //--------------------------------------------------------
        //  Role: guest, Resource: ALL, Rights: ALL
        //--------------------------------------------------------
        $acl->deny('guest', Resource::all(), Right::all());
        /* R: Herit allow from Role, r: Herit deny from Role, S: Herit from Resource, s: Herit deny from Resource, o: Deny, -: No rights
                  ||      home     ||   catalog     ||    import     ||    album      ||    track      ||
                  || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D ||
         | root   || - | - | - | - || - | x | - | - || - | S | - | - || - | S | x | - || - | S | o | - ||
         | admin  || - | - | - | - || - | x | - | - || x | S | - | x || - | S | R | - || - | S | o | - ||
         | dev    || - | - | - | - || - | x | - | - || R | S | - | R || - | S | R | - || - | S | o | - ||
         | edito  || - | x | - | - || - | x | - | - || R | x | - | R || - | x | R | - || - | x | o | - ||
         | guest  || o | o | o | o || o | o | o | o || o | o | o | o || o | o | o | o || o | o | o | o ||
        */
        $test = '
          ||     home      ||    catalog    ||    import     ||     album     ||     track     ||
          || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D ||
 | root   || - | - | - | - || - | x | - | - || - | x | - | - || - | x | x | - || - | x | - | - ||
 | admin  || - | - | - | - || - | x | - | - || x | x | - | x || - | x | x | - || - | x | - | - ||
 | dev    || - | - | - | - || - | x | - | - || x | x | - | x || - | x | x | - || - | x | - | - ||
 | edito  || - | x | - | - || - | x | - | - || x | x | - | x || - | x | x | - || - | x | - | - ||
 | guest  || - | - | - | - || - | - | - | - || - | - | - | - || - | - | - | - || - | - | - | - ||
';
        $this->assertEquals($test, $this->getTableRights($acl));

        //--------------------------------------------------------
        //  Role: edito, Resource: ALL, Rights: read, delete
        //--------------------------------------------------------
        $acl->deny('edito', Resource::all(), array(Right::get('read'), Right::get('delete')));
        /* R: Herit allow from Role, r: Herit deny from Role, S: Herit from Resource, s: Herit deny from Resource, o: Deny, -: No rights
                  ||      home     ||   catalog     ||    import     ||    album      ||    track      ||
                  || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D ||
         | root   || - | - | - | - || - | x | - | - || - | S | - | - || - | S | x | - || - | S | o | - ||
         | admin  || - | - | - | - || - | x | - | - || x | S | - | x || - | S | R | - || - | S | o | - ||
         | dev    || - | - | - | - || - | x | - | - || R | S | - | R || - | S | R | - || - | S | o | - ||
         | edito  || - | o | - | o || - | o | - | o || R | o | - | o || - | o | R | o || - | o | o | o ||
         | guest  || o | o | o | o || o | o | o | o || o | o | o | o || o | o | o | o || o | o | o | o ||
        */
        $test = '
          ||     home      ||    catalog    ||    import     ||     album     ||     track     ||
          || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D ||
 | root   || - | - | - | - || - | x | - | - || - | x | - | - || - | x | x | - || - | x | - | - ||
 | admin  || - | - | - | - || - | x | - | - || x | x | - | x || - | x | x | - || - | x | - | - ||
 | dev    || - | - | - | - || - | x | - | - || x | x | - | x || - | x | x | - || - | x | - | - ||
 | edito  || - | - | - | - || - | - | - | - || x | - | - | - || - | - | x | - || - | - | - | - ||
 | guest  || - | - | - | - || - | - | - | - || - | - | - | - || - | - | - | - || - | - | - | - ||
';
        $this->assertEquals($test, $this->getTableRights($acl));

        //--------------------------------------------------------
        //  Role: admin, Resource: import, Rights: read, delete
        //--------------------------------------------------------
        $acl->deny('admin', 'import', array(Right::get('read'), Right::get('delete')));
        /* R: Herit allow from Role, r: Herit deny from Role, S: Herit from Resource, s: Herit deny from Resource, o: Deny, -: No rights
                  ||      home     ||   catalog     ||    import     ||    album      ||    track      ||
                  || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D ||
         | root   || - | - | - | - || - | x | - | - || - | S | - | - || - | S | x | - || - | S | o | - ||
         | admin  || - | - | - | - || - | x | - | - || x | o | - | o || - | S | R | - || - | S | o | - ||
         | dev    || - | - | - | - || - | x | - | - || R | s | - | o || - | S | R | - || - | S | o | - ||
         | edito  || - | o | - | o || - | o | - | o || R | o | - | o || - | o | R | o || - | o | o | o ||
         | guest  || o | o | o | o || o | o | o | o || o | o | o | o || o | o | o | o || o | o | o | o ||
        */
        $test = '
          ||     home      ||    catalog    ||    import     ||     album     ||     track     ||
          || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D ||
 | root   || - | - | - | - || - | x | - | - || - | x | - | - || - | x | x | - || - | x | - | - ||
 | admin  || - | - | - | - || - | x | - | - || x | - | - | - || - | x | x | - || - | x | - | - ||
 | dev    || - | - | - | - || - | x | - | - || x | - | - | - || - | x | x | - || - | x | - | - ||
 | edito  || - | - | - | - || - | - | - | - || x | - | - | - || - | - | x | - || - | - | - | - ||
 | guest  || - | - | - | - || - | - | - | - || - | - | - | - || - | - | - | - || - | - | - | - ||
';
        $this->assertEquals($test, $this->getTableRights($acl));

        //--------------------------------------------------------
        //  Role: root, Resource: catalog, Rights: read
        //--------------------------------------------------------
        $acl->deny('root', 'catalog', array(Right::get('read'), Right::get('delete')));
        /* R: Herit allow from Role, r: Herit deny from Role, S: Herit from Resource, s: Herit deny from Resource, o: Deny, -: No rights
                  ||      home     ||   catalog     ||    import     ||    album      ||    track      ||
                  || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D ||
         | root   || - | - | - | - || - | o | - | o || - | s | - | s || - | s | x | s || - | s | o | s ||
         | admin  || - | - | - | - || - | x | - | r || x | o | - | o || - | S | R | - || - | S | o | - ||
         | dev    || - | - | - | - || - | x | - | r || R | s | - | o || - | S | R | - || - | S | o | - ||
         | edito  || - | o | - | o || - | o | - | o || R | o | - | o || - | o | R | o || - | o | o | o ||
         | guest  || o | o | o | o || o | o | o | o || o | o | o | o || o | o | o | o || o | o | o | o ||
        */
        $test = '
          ||     home      ||    catalog    ||    import     ||     album     ||     track     ||
          || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D ||
 | root   || - | - | - | - || - | - | - | - || - | - | - | - || - | - | x | - || - | - | - | - ||
 | admin  || - | - | - | - || - | x | - | - || x | - | - | - || - | x | x | - || - | x | - | - ||
 | dev    || - | - | - | - || - | x | - | - || x | - | - | - || - | x | x | - || - | x | - | - ||
 | edito  || - | - | - | - || - | - | - | - || x | - | - | - || - | - | x | - || - | - | - | - ||
 | guest  || - | - | - | - || - | - | - | - || - | - | - | - || - | - | - | - || - | - | - | - ||
';
        $this->assertEquals($test, $this->getTableRights($acl));
    }

    /**
     * Roles:
     *   root => admin => dev, edito, guest
     * Resources:
     *   home, catalog => import|album => track
     * Controls:
     *   create, read, update, delete
     *
     * Final array what we want :
     *          ||      home     ||   catalog     ||    import     ||    album      ||    track      ||
     *          || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D || C | R | U | D ||
     * | root   || x | x | x | x || x | x | x | x || x | x | x | x || x | x | x | x || x | x | x | x ||
     * | admin  || x | x | x | - || x | x | x | - || x | x | x | - || x | x | x | - || x | x | x | - ||
     * | dev    || - | x | - | - || - | x | - | - || x | x | x | x || - | x | - | - || - | x | - | - ||
     * | edito  || - | x | - | - || - | x | - | - || - | x | - | - || x | x | x | - || x | x | x | - ||
     * | guest  || - | - | - | - || - | - | - | - || - | - | - | - || - | - | - | - || - | - | - | - ||
     *
     * @param  Acl $acl
     * @param  array $roles
     * @param  array $resources
     * @param  array $rights
     * @return string
     */
    protected function getTableRights($acl, $roles = array(), $resources = array(), $rights = array())
    {
        if (empty($roles)) {
            $roles = array('root', 'admin', 'dev', 'edito', 'guest');
        }

        if (empty($resources)) {
            $resources = array('home', 'catalog', 'import', 'album', 'track');
        }

        if (empty($rights)) {
            $rights = array('create', 'read', 'update', 'delete');
        }

        $table = '
          ||';

        $padding = count($rights) * 4 - 1; // 4 Chars by rights
        foreach ($resources as $resource) {
            $table .= str_pad($resource, $padding, ' ', STR_PAD_BOTH) . '||';
        }
        $table .= PHP_EOL . '          ||';

        for ($index = 0, $max = count($resources); $index < $max; $index++) {
            foreach ($rights as $right) {
                $table .= ' ' . strtoupper(substr($right, 0, 1)) . ' |';
            }
            $table .= '|';
        }
        $table .= PHP_EOL;

        foreach ($roles as $role) {
            $line = sprintf(' | %-6s ||', $role);
            foreach ($resources as $resource) {
                foreach ($rights as $right) {
                    $right = ($acl->isAllowed($role, $resource, Right::get($right)) ? 'x' : '-');
                    $line .= sprintf(' %s |', $right);
                }
                $line .= '|';
            }
            $table .= $line . PHP_EOL;
        }

        return $table;
    }
}

