<?php
// Execute the reference implementation, rather than reproducing its algorithms.
require ($argv[1] ?? dirname(__DIR__, 2) . '/php-client') . '/vendor/autoload.php';
use Authwave\{Authenticator, Token, SessionData, RedirectHandler};
use Authwave\ResponseData\UserResponseData;
use GT\Cipher\InitVector;
use Psr\Http\Message\UriInterface;
class RecordingRedirect extends RedirectHandler {
 public array $redirects = [];
 public function redirect(UriInterface $uri, int $code = 303):void { $this->redirects[] = [(string)$uri, $code]; }
}
$cases = json_decode(stream_get_contents(STDIN), true);
$out = [];
foreach($cases as $index => $case) {

 $secret = str_repeat('s',32);
 $token = new Token($secret, (new InitVector())->withBytes(str_repeat('a',24)), (new InitVector())->withBytes(str_repeat('f',24)));
 $_SESSION = ['basket' => ['tea']];
 $redirect = new RecordingRedirect(); $calls = 0;
 $callback = function($user) use (&$calls, $case) { $calls++; if($case['throwCallback'] ?? false) throw new RuntimeException('callback'); };
 if(($case['state'] ?? '') === 'pending') $_SESSION[SessionData::class] = new SessionData($token, null, $case['returnQuery'] ?? null);
 if(($case['state'] ?? '') === 'user') $_SESSION[SessionData::class] = new SessionData($token, new UserResponseData('user-id', $case['email'] ?? 'person@example.com'));
 $uri = $case['uri'] ?? '/account?tab=security';
 if(isset($case['response'])) {
  $cipher = base64_encode(sodium_crypto_secretbox(json_encode($case['response']), str_repeat('a',24), $secret));
  $uri .= (str_contains($uri,'?') ? '&' : '?') . 'AUTHWAVE_RESPONSE_DATA=' . (($case['rawPlus'] ?? false) ? $cipher : urlencode($cipher));
 }
 $error = null; $auth = null;
 try {
  $auth = new Authenticator('deployment_with_underscores_'.$secret, $uri, $case['host'] ?? 'login.authwave.com', redirectHandler:$redirect, onAuthenticated:($case['callback'] ?? false) ? $callback : null);
  if(isset($case['returnUri'])) $auth->setReturnUri($case['returnUri']);
  if(($case['action'] ?? '') === 'login') $auth->login($token);
  if(($case['action'] ?? '') === 'logout') $auth->logout($case['redirectTo'] ?? null, $token);
 } catch(Throwable $e) { $error = (new ReflectionClass($e))->getShortName(); }
 $stored = $_SESSION[SessionData::class] ?? null; $userData = null;
 if($stored) { try { $d = $stored->getData(); $userData = [$d->getId(), $d->getEmail()]; } catch(Authwave\NotLoggedInException) {} }
 $user = $auth && $auth->isLoggedIn() ? [$auth->getAuthUser()->id, $auth->getAuthUser()->email] : null;
 $out[] = ['redirects'=>$redirect->redirects, 'calls'=>$calls, 'error'=>$error, 'user'=>$user, 'stored'=>$stored !== null, 'data'=>$userData, 'returnQuery'=>$stored?->getReturnQuery(), 'invoked'=>$stored?->hasInvokedAuthenticationCallback(), 'basket'=>$_SESSION['basket']];
}
echo json_encode($out, JSON_THROW_ON_ERROR);
