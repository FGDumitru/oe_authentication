<?php

declare(strict_types = 1);

namespace Drupal\oe_authentication_eulogin_mock\Controller;

use Drupal\cas\Event\CasPreValidateEvent;
use Drupal\cas\Service\CasHelper;
use Drupal\cas_mock_server\Controller\CasMockServerController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

/**
 * Returns responses for EuLogin mock server routes.
 */
class EuLoginMockServerController extends CasMockServerController {

  /**
   * Validates a service ticket.
   *
   * We are using this instead of the validate() method of the
   * CasMockServerController to call pre validate event in order to assert the
   * validation parameters as well.
   *
   * @see CasMockServerController::validate()
   */
  public function validateTicket(): Response {
    $request = $this->requestStack->getCurrentRequest();

    // If there is no service ticket we can not validate anything.
    if (!$request->query->has('ticket')) {
      throw new NotFoundHttpException();
    }

    // Locate the user that issued the given ticket.
    $ticket = $request->query->get('ticket');

    // Dispatch the pre validation event to assert related logics where modules
    // alter the validation path or URL parameters.
    $params['ticket'] = $ticket;
    $pre_validate_event = new CasPreValidateEvent('p3/serviceValidate', $params);
    $this->eventDispatcher->dispatch(CasHelper::EVENT_PRE_VALIDATE, $pre_validate_event);

    // We are doing this in order to mimic the CAS behaviour that adds the
    // validation parameters to the query string, so we can assert them in test.
    // @see CasValidator::validateTicket()
    if (!empty($pre_validate_event->getParameters())) {
      $request->query->add($pre_validate_event->getParameters());
    }

    if (!$user_data = $this->userManager->getUserByServiceTicket($ticket)) {
      throw new NotFoundHttpException();
    }

    return Response::create($this->getContent($user_data));
  }

}
