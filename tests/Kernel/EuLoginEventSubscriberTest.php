<?php

declare(strict_types = 1);

namespace Drupal\Tests\oe_authentication\Kernel;

use Drupal\Core\Url;
use Drupal\KernelTests\KernelTestBase;
use Symfony\Component\HttpFoundation\Request;

/**
 * Tests the login redirect happens with the expected parameters.
 *
 * @group oe_authentication
 */
class EuLoginEventSubscriberTest extends KernelTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'cas',
    'cas_mock_server',
    'externalauth',
    'oe_authentication',
    'oe_authentication_eulogin_mock',
    'path_alias',
    'system',
    'user',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installSchema('system', ['key_value_expire']);
    $this->installConfig(['cas', 'cas_mock_server', 'oe_authentication']);
  }

  /**
   * Tests the two-factor authentication parameter is not applied by default.
   *
   * @covers EuLoginEventSubscriber::forceTwoFactorAuthentication()
   */
  public function testDefaultNo2faRedirectParameterAdded(): void {
    $request = Request::create(Url::fromRoute('user.login')->toString(TRUE)->getGeneratedUrl());
    $response = $this->container->get('http_kernel')->handle($request);
    $this->assertEquals(200, $response->getStatusCode());
    $redirect_string = 'acceptStrengths';
    $this->assertStringNotContainsString($redirect_string, $response->getContent());
  }

  /**
   * Tests the two-factor authentication parameters.
   *
   * This and the testDefaultNo2faRedirectParameterAdded() are separate
   * because in kernel test two consecutive requests are not rebuilding the
   * http_kernel and they are executed in the same execution thread, so the
   * config value (forced_login) that is in the CasSubscriber::__construct()
   * will have the old value during the upcoming request.
   *
   * @covers EuLoginEventSubscriber::forceTwoFactorAuthentication()
   */
  public function test2faRedirectParameter(): void {
    $config_factory = $this->container->get('config.factory');
    $config_factory->getEditable('cas.settings')->set('forced_login.enabled', TRUE)->save();
    $config_factory->getEditable('oe_authentication.settings')->set('force_2fa', TRUE)->save();
    $request = Request::create(Url::fromRoute('user.login')->toString(TRUE)->getGeneratedUrl());
    $response = $this->container->get('http_kernel')->handle($request);
    $this->assertEquals(302, $response->getStatusCode());
    $redirect_string = 'Redirecting to https:/login?acceptStrengths=PASSWORD_MOBILE_APP%2CPASSWORD_SOFTWARE_TOKEN%2CPASSWORD_SMS&amp;service=http%3A//localhost/casservice%3Fdestination%3D/user/login';
    $this->assertStringContainsString($redirect_string, $response->getContent());
  }

  /**
   * Tests that the validation request has the correct parameters.
   *
   * @covers EuLoginEventSubscriber::alterValidationPath()
   */
  public function testValidationParameters(): void {
    // Set up a test user with a service ticket.
    $ticket = 'ST-123456789';
    $user_data = [
      'username' => 'sharon',
      'email' => 'sharon@example.com',
      'password' => 'hunter2',
      'groups' => 'COMM_CEM, EDITORS,USERS ',
    ];
    $userManager = $this->container->get('cas_mock_server.user_manager');
    $userManager->addUser($user_data);
    $userManager->assignServiceTicket('sharon', $ticket);

    // Request to validate the ticket.
    $request = Request::create(Url::fromRoute('oe_authentication_eulogin_mock.validate', [], [
      'query' => [
        'ticket' => $ticket,
      ],
    ])->toString(TRUE)->getGeneratedUrl());

    $this->container->get('http_kernel')->handle($request);

    // Assert the validation parameters.
    $expected = [
      'ticket' => 'ST-123456789',
      'assuranceLevel' => 'TOP',
      'ticketTypes' => 'SERVICE,PROXY',
      'userDetails' => 'true',
      'groups' => '*',
    ];
    $this->assertSame($expected, $request->query->all());

    $this->container->get('config.factory')->getEditable('oe_authentication.settings')->set('force_2fa', TRUE)->save();
    $this->container->get('http_kernel')->handle($request);

    // Assert the validation parameters.
    $expected = [
      'ticket' => 'ST-123456789',
      'assuranceLevel' => 'TOP',
      'ticketTypes' => 'SERVICE,PROXY',
      'userDetails' => 'true',
      'groups' => '*',
      'acceptStrengths' => 'PASSWORD_MOBILE_APP,PASSWORD_SOFTWARE_TOKEN,PASSWORD_SMS',
    ];
    $this->assertSame($expected, $request->query->all());
  }

}
