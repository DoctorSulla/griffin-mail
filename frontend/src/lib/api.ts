import { dev } from '$app/environment';

const API_BASE_URL = dev ? 'http://localhost:3000' : '';

export interface Recipient {
	id?: number;
	name: string;
	email: string;
}

export interface MailingList {
	id: number;
	name: string;
	description: string;
}

export interface ListWithRecipients {
	list: MailingList;
	recipients: Required<Recipient>[];
}

export type ListPermission = 'read' | 'write' | 'send' | 'change_permission';
export type GlobalPermission = 'manage_list' | 'manage_recipient' | 'change_permission';

export interface UserPermission {
	user_email: string;
	permission: ListPermission | GlobalPermission;
}

export interface ListEmailRequest {
	subject: string;
	body: string;
	from?: string;
	reply_to?: string;
}

export interface GoogleLoginRequest {
	jwt: string;
}

export interface LoginRequest {
	email: string;
	password: string;
}

export interface RegisterRequest {
	email: string;
	username: string;
	password: string;
	confirm_password: string;
}

export interface VerifyEmailRequest {
	email: string;
	code: string;
}

export interface ChangePasswordRequest {
	old_password: string;
	password: string;
	confirm_password: string;
}

export interface ConfirmPasswordReset {
	code: string;
	password: string;
	confirm_password: string;
}

export interface ApiResponse {
	response_type: string;
	message: string;
}

export interface ResourceResult<T = undefined> {
	ok: boolean;
	message: string;
	data?: T;
}

async function apiCall(
	endpoint: string,
	method: 'GET' | 'POST' | 'PATCH' | 'DELETE',
	body?: any
): Promise<ApiResponse> {
	try {
		const response = await fetch(`${API_BASE_URL}${endpoint}`, {
			method,
			headers: {
				'Content-Type': 'application/json'
			},
			credentials: 'include',
			body: body ? JSON.stringify(body) : undefined
		});

		if (!response.ok) {
			const error = await response.json().catch(() => {
				return { response_type: 'Error', message: 'Request failed' };
			});
			return error;
		} else if (response.status == 204) {
			return { response_type: 'SuccessNoContent', message: '' };
		}

		const data = await response.json();
		return data;
	} catch (error) {
		return { response_type: 'Error', message: 'Network request failed' };
	}
}

async function resourceCall<T>(
	endpoint: string,
	method: 'GET' | 'POST' | 'PATCH' | 'DELETE' = 'GET',
	body?: unknown
): Promise<ResourceResult<T>> {
	try {
		const response = await fetch(`${API_BASE_URL}${endpoint}`, {
			method,
			headers: { 'Content-Type': 'application/json' },
			credentials: 'include',
			body: body === undefined ? undefined : JSON.stringify(body)
		});

		if (response.status === 204) {
			return { ok: true, message: '' };
		}

		const payload = await response.json().catch(() => null);
		if (!response.ok || payload?.response_type === 'Error') {
			return {
				ok: false,
				message: payload?.message ?? `Request failed (${response.status})`
			};
		}

		return { ok: true, message: payload?.message ?? '', data: payload as T };
	} catch {
		return { ok: false, message: 'Network request failed' };
	}
}

export const api = {
	async getNonce(): Promise<ApiResponse> {
		return apiCall('/nonce', 'GET', null);
	},

	async login(credentials: LoginRequest): Promise<ApiResponse> {
		return apiCall('/account/login', 'POST', credentials);
	},

	async googleLogin(jwt: GoogleLoginRequest): Promise<ApiResponse> {
		return apiCall('/account/login/google', 'POST', jwt);
	},

	async logout() {
		await fetch(`${API_BASE_URL}/account/logout`, {
			credentials: 'include'
		});
	},

	async register(userData: RegisterRequest): Promise<ApiResponse> {
		return apiCall('/account/register', 'POST', userData);
	},

	async verifyEmail(verifyEmail: VerifyEmailRequest): Promise<ApiResponse> {
		return apiCall('/account/verifyEmail', 'POST', verifyEmail);
	},

	async changePassword(changePasswordRequest: ChangePasswordRequest): Promise<ApiResponse> {
		return apiCall('/account/changePassword', 'PATCH', changePasswordRequest);
	},

	async resetPassword(email: string): Promise<ApiResponse> {
		return apiCall('/account/resetPassword', 'POST', email);
	},

	async completeResetPassword(confirmPasswordReset: ConfirmPasswordReset): Promise<ApiResponse> {
		return apiCall('/account/resetPassword', 'PATCH', confirmPasswordReset);
	},

	async getProfile(): Promise<ApiResponse> {
		return apiCall('/account/profile', 'GET', null);
	},

	async resendVerificationEmail(): Promise<ApiResponse> {
		return apiCall('/account/verificationEmail', 'GET');
	},

	async addRecipients(recipients: Recipient[]): Promise<ApiResponse> {
		return apiCall('/email/recipients', 'POST', recipients);
	},

	async getRecipients(): Promise<ResourceResult<Required<Recipient>[]>> {
		return resourceCall('/email/recipients');
	},

	async deleteRecipient(email: string): Promise<ResourceResult> {
		return resourceCall(`/email/recipients/${encodeURIComponent(email)}`, 'DELETE');
	},

	async getLists(): Promise<ResourceResult<MailingList[]>> {
		return resourceCall('/email/lists');
	},

	async getList(id: number): Promise<ResourceResult<ListWithRecipients>> {
		return resourceCall(`/email/lists/${id}`);
	},

	async createList(list: Omit<MailingList, 'id'>): Promise<ResourceResult<MailingList>> {
		return resourceCall('/email/lists', 'POST', list);
	},

	async deleteList(id: number): Promise<ResourceResult> {
		return resourceCall(`/email/lists/${id}`, 'DELETE');
	},

	async getAvailableRecipients(id: number): Promise<ResourceResult<Required<Recipient>[]>> {
		return resourceCall(`/email/lists/${id}/recipients/available`);
	},

	async addRecipientsToList(id: number, recipientIds: number[]): Promise<ResourceResult> {
		return resourceCall(`/email/lists/${id}/recipients`, 'POST', recipientIds);
	},

	async removeRecipientsFromList(id: number, recipientIds: number[]): Promise<ResourceResult> {
		return resourceCall(`/email/lists/${id}/recipients`, 'DELETE', recipientIds);
	},

	async sendEmailToList(id: number, email: ListEmailRequest): Promise<ResourceResult> {
		return resourceCall(`/email/lists/${id}`, 'POST', email);
	},

	async getListPermissions(id: number): Promise<ResourceResult<UserPermission[]>> {
		return resourceCall(`/email/lists/${id}/permissions`);
	},

	async addListPermissions(id: number, permissions: UserPermission[]): Promise<ResourceResult> {
		return resourceCall(`/email/lists/${id}/permissions`, 'POST', permissions);
	},

	async deleteListPermissions(id: number, permissions: UserPermission[]): Promise<ResourceResult> {
		return resourceCall(`/email/lists/${id}/permissions`, 'DELETE', permissions);
	},

	async addGlobalPermissions(permissions: UserPermission[]): Promise<ResourceResult> {
		return resourceCall('/email/users/permissions', 'POST', permissions);
	},

	async deleteGlobalPermissions(permissions: UserPermission[]): Promise<ResourceResult> {
		return resourceCall('/email/users/permissions', 'DELETE', permissions);
	},

	async unsubscribe(
		unsubscribeText: string,
		unsubscribeSignature: string
	): Promise<ResourceResult> {
		return resourceCall('/unsubscribe', 'POST', {
			unsubscribe_text: unsubscribeText,
			unsubscribe_signature: unsubscribeSignature
		});
	}
};
