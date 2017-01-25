<?php
/**
 * @copyright Copyright (c) 2017 Joas Schilling <coding@schilljs.com>
 *
 * @license GNU AGPL version 3 or any later version
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

namespace OC\Security\IdentityProof;

use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IUser;
use OCP\IUserManager;

class Crypto {
	/** @var Manager */
	private $keyManager;
	/** @var ITimeFactory */
	private $timeFactory;
	/** @var IUserManager */
	private $userManager;

	/**
	 * @param Manager $keyManager
	 * @param ITimeFactory $timeFactory
	 * @param IUserManager $userManager
	 */
	public function __construct(Manager $keyManager,
								ITimeFactory $timeFactory,
								IUserManager $userManager) {
		$this->keyManager = $keyManager;
		$this->timeFactory = $timeFactory;
		$this->userManager = $userManager;
	}

	/**
	 * Returns a signed blob for $data
	 *
	 * @param string $data
	 * @param IUser $user
	 * @return array ['message', 'signature']
	 */
	public function encrypt($data, IUser $user) {
		$privateKey = $this->keyManager->getKey($user)->getPrivate();
		openssl_private_encrypt($data, $encryptedData, $privateKey, OPENSSL_PKCS1_OAEP_PADDING);
		openssl_sign($data, $signature, $privateKey, OPENSSL_ALGO_SHA512);

		return [
			'message' => $encryptedData,
			'signature' => $signature,
		];
	}

	/**
	 * Return the decrypted message
	 *
	 * @param array  $data
	 * @param IUser $user
	 * @return bool
	 * @throws \InvalidArgumentException
	 */
	public function decrypt($data, IUser $user) {

		if (!$this->verify($data, $user)) {
			throw new \InvalidArgumentException('Invalid signature');
		}

		$privateKey = $this->keyManager->getKey($user)->getPrivate();
		if (!openssl_private_decrypt($data['message'], $plainText, $privateKey, OPENSSL_PKCS1_OAEP_PADDING)) {
			throw new \InvalidArgumentException('Failed to decrypt message for given user');
		}

		return $plainText;
	}

	/**
	 * Whether the data is encrypted properly
	 *
	 * @param array  $data
	 * @param IUser $user
	 * @return bool
	 */
	public function verify(array $data, IUser $user) {
		$key = $this->keyManager->getKey($user);

		return (bool)openssl_verify(
			$data['message'],
			$data['signature'],
			$key->getPublic(),
			OPENSSL_ALGO_SHA512
		);
	}
}
