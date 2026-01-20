import type {
	ICredentialDataDecryptedObject,
	ICredentialTestRequest,
	ICredentialType,
	IDataObject,
	IHttpRequestHelper,
	INodeProperties,
} from 'n8n-workflow';

export class InstagramOAuth2Api implements ICredentialType {
	name = 'instagramOAuth2Api';
	extends = ['oAuth2Api'];
	displayName = 'Instagram OAuth2 API';
	documentationUrl = 'https://developers.facebook.com/docs/instagram-api/getting-started';
	properties: INodeProperties[] = [
		{
			displayName: 'Grant Type',
			name: 'grantType',
			type: 'hidden',
			default: 'authorizationCode',
		},
		{
			displayName: 'Authorization URL',
			name: 'authUrl',
			type: 'hidden',
			default: 'https://api.instagram.com/oauth/authorize',
		},
		{
			displayName: 'Access Token URL',
			name: 'accessTokenUrl',
			type: 'hidden',
			default: 'https://api.instagram.com/oauth/access_token',
		},
		{
			displayName: 'Scope',
			name: 'scope',
			type: 'hidden',
			default: 'instagram_business_basic,instagram_business_manage_messages,instagram_business_manage_comments,instagram_business_content_publish',
		},
		{
			displayName: 'Auth URI Query Parameters',
			name: 'authQueryParameters',
			type: 'hidden',
			default: '',
		},
		{
			displayName: 'Authentication',
			name: 'authentication',
			type: 'hidden',
			default: 'body',
		},
		{
			displayName: 'Account Information',
			name: 'accountInfoNotice',
			type: 'notice',
			default: '',
			description: 'After connecting your account, your Instagram Business Account details (username, ID, profile) will be automatically available. You can access this information in your workflow nodes. The system will automatically exchange your OAuth token for a long-lived token (60 days) and persist it, ensuring it survives n8n restarts.',
		},
		{
			displayName: 'Client ID',
			name: 'clientId',
			type: 'string',
			default: '',
			required: true,
			description: 'The Instagram App ID from your Meta Developer Console. <a href="https://developers.facebook.com/apps/" target="_blank">Get it here</a>.',
			placeholder: '1234567890123456',
		},
		{
			displayName: 'Client Secret',
			name: 'clientSecret',
			type: 'string',
			typeOptions: {
				password: true,
			},
			default: '',
			required: true,
			description: 'The Instagram App Secret from your Meta Developer Console',
			placeholder: 'abc123def456...',
		},
		{
			displayName: 'Webhook Verify Token',
			name: 'webhookVerifyToken',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			required: false,
			description: 'Optional: Custom verification token for webhook setup (minimum 20 characters). Only needed if using Instagram Trigger node.',
			placeholder: 'my_custom_verify_token_2024',
		},
		// Hidden field for long-lived token with expirable typeOption
		// This enables n8n's preAuthentication system to persist the token
		{
			displayName: 'Long-Lived Token',
			name: 'longLivedToken',
			type: 'hidden',
			typeOptions: {
				expirable: true,
			},
			default: '',
		},
		{
			displayName: 'Token Expires At',
			name: 'tokenExpiresAt',
			type: 'hidden',
			default: 0,
		},
	];

	/**
	 * Pre-authentication hook that exchanges short-lived OAuth token for a long-lived token
	 * and refreshes it when near expiration. n8n automatically persists the returned values.
	 *
	 * This is called by n8n before each API request when the credential has an expirable field.
	 * If this function returns new credential data, n8n will persist it to the database.
	 */
	async preAuthentication(
	this: IHttpRequestHelper,
	credentials: ICredentialDataDecryptedObject,
): Promise<IDataObject> {
	const now = Math.floor(Date.now() / 1000);
	const longLivedToken = credentials.longLivedToken as string;
	const tokenExpiresAt = (credentials.tokenExpiresAt as number) || 0;
	const clientSecret = credentials.clientSecret as string;
	const clientId = credentials.clientId as string;
	const oauthTokenData = credentials.oauthTokenData as { access_token?: string } | undefined;
	const shortLivedToken = oauthTokenData?.access_token;

	// 1. Se já temos um token válido e longe de expirar (mais de 3 dias), não faz nada.
	if (longLivedToken && tokenExpiresAt > now + (3 * 24 * 60 * 60)) {
		return {};
	}

	// 2. Se não temos token curto para trocar, aborta.
	if (!shortLivedToken) {
		return {};
	}

	// 3. Tenta trocar o Token Curto (ou o próprio Longo antigo) por um NOVO Token Longo
	// Usamos a API do Facebook (graph.facebook.com) e não do Instagram
	try {
		const tokenToExchange = longLivedToken || shortLivedToken;

		const response = await this.helpers.httpRequest({
			method: 'GET',
			url: 'https://graph.facebook.com/v20.0/oauth/access_token',
			qs: {
				grant_type: 'fb_exchange_token',
				client_id: clientId,
				client_secret: clientSecret,
				fb_exchange_token: tokenToExchange,
			},
		}) as { access_token: string; expires_in: number };

		if (response.access_token) {
			return {
				longLivedToken: response.access_token,
				tokenExpiresAt: now + response.expires_in,
			};
		}
	} catch (error) {
		console.error('Instagram Business: Failed to exchange token', error);
		return {};
	}

	return {};
}


	/**
	 * Test the credentials to ensure they work
	 */
	test: ICredentialTestRequest = {
	request: {
		baseURL: 'https://graph.facebook.com/v20.0',
		url: '/me',
		method: 'GET',
		qs: {
			fields: 'id,name',
		},
	},
};

}
