<script lang="ts">
	import { afterNavigate } from '$app/navigation';
	import { api } from '$lib/api';
	import { goto } from '$app/navigation';
	import type { Profile } from '$lib/profile';

	let loading = false;
	let error = '';
	let success = '';

	let email = '';
	let code = '';

	let changePasswordRequest = {
		old_password: '',
		password: '',
		confirm_password: ''
	};

	const dateOptions: Intl.DateTimeFormatOptions = {
		year: 'numeric',
		month: 'long',
		day: 'numeric'
	};

	async function changePassword(event: SubmitEvent) {
		event.preventDefault();
		loading = true;
		let result = await api.changePassword(changePasswordRequest);

		if (result.response_type == 'Error') {
			error = result.message;
			success = '';
		} else {
			success = result.message;
			error = '';
			changePasswordRequest.old_password = '';
			changePasswordRequest.password = '';
			changePasswordRequest.confirm_password = '';
		}
		loading = false;
	}

	async function verifyEmail(event: SubmitEvent) {
		event.preventDefault();
		loading = true;
		let result = await api.verifyEmail({
			email: email,
			code: code
		});

		if (result.response_type == 'Error') {
			error = result.message;
		} else {
			error = '';
			goto('/profile');
		}
		loading = false;
	}

	async function resendVerificationEmail() {
		loading = true;
		error = '';
		success = '';
		const result = await api.resendVerificationEmail();
		if (result.response_type === 'Error') {
			error = result.message;
		} else {
			success = result.message;
		}
		loading = false;
	}

	let profile: Profile | null = null;
	afterNavigate(async function () {
		let response = await api.getProfile();
		if (response.response_type == 'Error') {
			goto('/login');
		} else {
			profile = JSON.parse(response.message);
			if (profile?.email) {
				email = profile.email;
			}
		}
	});
</script>

{#if profile}
	<h1 class="text-2xl">Welcome {profile.username}</h1>
	<ul>
		{#if !profile.email_verified}
			<li>Email: {email} <span class="text-red-500">&times; Unverified</span></li>
			<li>
				<form onsubmit={verifyEmail}>
					<input
						class="border border-blue-200"
						type="text"
						name="code"
						placeholder="Enter verification code"
						bind:value={code}
					/>

					<input type="hidden" bind:value={email} name="email" required />
					<button class="cursor-pointer rounded-2xl bg-blue-400 p-1 text-white">Verify Email</button
					>
				</form>
				<button
					type="button"
					disabled={loading}
					onclick={resendVerificationEmail}
					class="mt-2 cursor-pointer text-sm font-medium text-blue-600 hover:text-blue-800 disabled:opacity-50"
				>
					Resend verification email
				</button>
			</li>
		{:else}
			<li>Email: {email} <span class="text-green-500">&check; Verified</span></li>
			<li>
				Registration date: {new Date(profile.registration_ts * 1000).toLocaleString(
					'en-GB',
					dateOptions
				)}
			</li>
			{#if profile.identity_provider == 'default'}
				<li>
					<h1 class="text-2xl">Change password:</h1>
					<form onsubmit={changePassword}>
						<input
							class="my-2 block border border-blue-200"
							bind:value={changePasswordRequest.old_password}
							type="password"
							name="old_password"
							placeholder="Old password"
							required
						/>

						<input
							class="my-2 block border border-blue-200"
							bind:value={changePasswordRequest.password}
							type="password"
							name="password"
							placeholder="New password"
							required
						/>
						<input
							class="my-2 block border border-blue-200"
							bind:value={changePasswordRequest.confirm_password}
							type="password"
							name="confirm_password"
							placeholder="Confirm new password"
							required
						/>
						<button class="cursor-pointer rounded-2xl bg-blue-400 p-1 text-white"
							>Change Password</button
						>
					</form>
				</li>
			{/if}
		{/if}
	</ul>

	{#if error}
		<div class="text-sm text-red-600">{error}</div>
	{/if}

	{#if success}
		<div class="text-sm text-green-600">{success}</div>
	{/if}
{/if}

<style>
	li {
		margin: 5px 0;
	}
</style>
