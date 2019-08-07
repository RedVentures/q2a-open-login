<?php

/* !
 * HybridAuth
 * http://hybridauth.sourceforge.net | http://github.com/hybridauth/hybridauth
 * (c) 2009-2012, HybridAuth authors | http://hybridauth.sourceforge.net/licenses.html
 */

/**
 * Auth0 OAuth Class.
 *
 * @package  HybridAuth providers package
 * @author   Lukasz Koprowski <azram19@gmail.com>
 * @author   Oleg Kuzava <olegkuzava@gmail.com>
 * @author   Tory Walker <toryjwalker@gmail.com>
 * @version  1.0
 * @license  BSD License
 */

/**
 * Hybrid_Providers_Auth0 - Auth0 provider adapter based on OAuth2 protocol.
 */
class Hybrid_Providers_Auth0 extends Hybrid_Provider_Model_OAuth2
{
  /**
   * Define Auth0 scopes
   *
   * @var array $string
   *   Default to just retrieve openid & profile
   */
  public $scope = 'openid profile';

  /**
   * Define Auth0 audience
   *
   * @var array $audience
   *   Audience needed to get profile
   */
  public $audience;

  /**
   * {@inheritdoc}
   */
  function initialize()
  {
    if (!$this->config["keys"]["id"] || !$this->config["keys"]["secret"] || !$this->config["keys"]["tenant"] || !$this->config["keys"]["audience"]) {
      throw new Exception("Your CLIENT_ID, CLIENT_SECRET, AUDIENCE, and TENANT are required to connect to {$this->providerId}.", 4);
    }

    // Set audience
    $this->audience = $this->config["keys"]["audience"];

    // Set scope from config
    if (isset($this->config["scope"])) {
      $this->scope = "{$this->scope} {$this->config["scope"]}";
    }

    // Include OAuth2 client
    require_once Hybrid_Auth::$config["path_libraries"] . "OAuth/OAuth2Client.php";

    // Create a new OAuth2 client instance
    $this->api = new OAuth2Client(
      $this->config["keys"]["id"],
      $this->config["keys"]["secret"],
      $this->endpoint,
      $this->compressed
    );

    // Provider api end-points.
    $this->api->api_base_url = "https://{$this->config['keys']['tenant']}.auth0.com/";
    $this->api->authorize_url = "https://{$this->config['keys']['tenant']}.auth0.com/authorize";
    $this->api->token_url = "https://{$this->config['keys']['tenant']}.auth0.com/oauth/token";

    // If we have an access token, set it
    if ($this->token("access_token")) {
      $this->api->access_token = $this->token("access_token");
      $this->api->refresh_token = $this->token("refresh_token");
      $this->api->access_token_expires_in = $this->token("expires_in");
      $this->api->access_token_expires_at = $this->token("expires_at");

      // Set token headers.
      $this->setAuthorizationHeaders();
    }
  }

  /**
   * {@inheritdoc}
   */
  function loginBegin()
  {
    // Redirect the user to the provider authentication url
    Hybrid_Auth::redirect($this->api->authorizeUrl(array("scope" => $this->scope, "audience" => $this->audience)));
  }

  /**
   * {@inheritdoc}
   */
  function getUserProfile()
  {
    // Set token headers.
    $this->setAuthorizationHeaders();

    // Request user profile data
    $response = $this->api->request("{$this->api->api_base_url}userinfo");
    $userProfile = json_decode($response);

    // Auth0 always returns a sub upon valid request
    if (!isset($userProfile->sub)) {
      throw new Exception("User profile request failed! {$this->providerId} returned an invalid response: " . Hybrid_Logger::dumpData($response), 6);
    }

    $this->user->profile->identifier = isset($userProfile->sub) ? $userProfile->sub : "";
    $this->user->profile->firstName = isset($userProfile->given_name) ? $userProfile->given_name : "";
    $this->user->profile->lastName = isset($userProfile->family_name) ? $userProfile->family_name : "";
    $this->user->profile->displayName = "{$userProfile->given_name} {$userProfile->family_name}";
    $this->user->profile->email = isset($userProfile->name) ? $userProfile->name : "";
    $this->user->profile->age = isset($userProfile->displayAge) ? $userProfile->displayAge : "";
    $this->user->profile->photoURL = isset($userProfile->picture) ? $userProfile->image->picture : "";

    return $this->user->profile;
  }

  /**
   * Returns current user id.
   *
   * @return string
   *   Current user ID.
   * @throws Exception
   */
  function getCurrentUserId()
  {
    return $this->user->profile->identifier;
  }

  /**
   * Set correct Authorization headers.
   *
   * @return void
   */
  private function setAuthorizationHeaders()
  {
    // Auth0 API requires the token to be passed as a Bearer within the authorization header.
    $this->api->curl_header = array(
      "Authorization: Bearer {$this->api->access_token}",
    );
  }
}
