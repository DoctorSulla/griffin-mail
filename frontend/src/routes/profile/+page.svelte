<script lang="ts">
	import { afterNavigate } from '$app/navigation';
	import { api } from '$lib/api';
	import { goto } from '$app/navigation';
	import type { Profile } from '$lib/profile';
	import Feedback from '$lib/Feedback.svelte';
	import User from '@lucide/svelte/icons/user';
	import Mail from '@lucide/svelte/icons/mail';
	import CalendarDays from '@lucide/svelte/icons/calendar-days';
	import BadgeCheck from '@lucide/svelte/icons/badge-check';
	import ShieldCheck from '@lucide/svelte/icons/shield-check';
	import KeyRound from '@lucide/svelte/icons/key-round';
	import Send from '@lucide/svelte/icons/send';

	let loading = false;
	let profileLoading = true;
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
		error = '';
		success = '';
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
		error = '';
		success = '';
		let result = await api.verifyEmail({
			email: email,
			code: code
		});

		if (result.response_type == 'Error') {
			error = result.message;
		} else {
			error = '';
			success = result.message;
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
		profileLoading = true;
		let response = await api.getProfile();
		if (response.response_type == 'Error') {
			goto('/login');
		} else {
			profile = JSON.parse(response.message);
			if (profile?.email) {
				email = profile.email;
			}
		}
		profileLoading = false;
	});

	function initials(username: string) {
		return username
			.split(/[\s._-]+/)
			.filter(Boolean)
			.slice(0, 2)
			.map((part) => part[0])
			.join('')
			.toUpperCase();
	}
</script>

{#if profileLoading}
	<div class="flex min-h-80 items-center justify-center" aria-live="polite">
		<div class="text-center">
			<div
				class="mx-auto size-8 animate-spin rounded-full border-4 border-blue-100 border-t-blue-600"
			></div>
			<p class="mt-3 text-sm text-gray-500">Loading your profile…</p>
		</div>
	</div>
{:else if profile}
	<div class="py-8">
		<section
			class="overflow-hidden rounded-2xl border border-blue-100 bg-white shadow-sm"
			aria-labelledby="profile-heading"
		>
			<div class="h-28 bg-gradient-to-r from-blue-700 via-blue-600 to-indigo-600"></div>
			<div class="px-6 pb-6 sm:px-8">
				<div class="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
					<div class="flex items-end gap-4">
						<div
							class="-mt-12 flex size-24 shrink-0 items-center justify-center rounded-2xl border-4 border-white bg-blue-50 text-3xl font-bold text-blue-700 shadow-sm"
							aria-hidden="true"
						>
							{initials(profile.username)}
						</div>
						<div class="pb-1">
							<h1 id="profile-heading" class="text-2xl font-bold text-gray-900 sm:text-3xl">
								{profile.username}
							</h1>
							<p class="mt-1 text-gray-500">Your Griffin Mail account</p>
						</div>
					</div>
					<span
						class="inline-flex w-fit items-center gap-1.5 rounded-full px-3 py-1 text-sm font-medium"
						class:bg-green-50={profile.email_verified}
						class:text-green-700={profile.email_verified}
						class:bg-amber-50={!profile.email_verified}
						class:text-amber-700={!profile.email_verified}
					>
						{#if profile.email_verified}
							<BadgeCheck size={16} />
							Email verified
						{:else}
							<Mail size={16} />
							Verification needed
						{/if}
					</span>
				</div>
			</div>
		</section>

		<div class="mt-6">
			<Feedback {error} {success} />
		</div>

		<div class="mt-6 grid gap-6 lg:grid-cols-5">
			<section
				class="rounded-xl border border-gray-200 bg-white p-6 shadow-sm lg:col-span-2"
				aria-labelledby="account-details-heading"
			>
				<div class="flex items-center gap-3">
					<div class="rounded-lg bg-blue-50 p-2 text-blue-600"><User size={20} /></div>
					<div>
						<h2 id="account-details-heading" class="font-semibold text-gray-900">
							Account details
						</h2>
						<p class="text-sm text-gray-500">Your personal account information</p>
					</div>
				</div>

				<dl class="mt-6 divide-y divide-gray-100">
					<div class="flex gap-3 py-4 first:pt-0">
						<Mail class="mt-0.5 shrink-0 text-gray-400" size={18} />
						<div class="min-w-0">
							<dt class="text-xs font-medium tracking-wide text-gray-500 uppercase">
								Email address
							</dt>
							<dd class="mt-1 truncate text-sm font-medium text-gray-900">{email}</dd>
						</div>
					</div>
					<div class="flex gap-3 py-4">
						<CalendarDays class="mt-0.5 shrink-0 text-gray-400" size={18} />
						<div>
							<dt class="text-xs font-medium tracking-wide text-gray-500 uppercase">
								Member since
							</dt>
							<dd class="mt-1 text-sm font-medium text-gray-900">
								{new Date(profile.registration_ts * 1000).toLocaleString('en-GB', dateOptions)}
							</dd>
						</div>
					</div>
					<div class="flex gap-3 py-4 last:pb-0">
						<ShieldCheck class="mt-0.5 shrink-0 text-gray-400" size={18} />
						<div>
							<dt class="text-xs font-medium tracking-wide text-gray-500 uppercase">
								Sign-in method
							</dt>
							<dd class="mt-1 text-sm font-medium text-gray-900">
								{profile.identity_provider === 'default'
									? 'Email and password'
									: profile.identity_provider}
							</dd>
						</div>
					</div>
				</dl>
			</section>

			<section
				class="rounded-xl border border-gray-200 bg-white p-6 shadow-sm lg:col-span-3"
				aria-labelledby="security-heading"
			>
				<div class="flex items-center gap-3">
					<div class="rounded-lg bg-blue-50 p-2 text-blue-600"><KeyRound size={20} /></div>
					<div>
						<h2 id="security-heading" class="font-semibold text-gray-900">
							{profile.email_verified ? 'Password & security' : 'Verify your email'}
						</h2>
						<p class="text-sm text-gray-500">
							{profile.email_verified
								? 'Keep your account secure with a strong password'
								: 'Complete verification to secure your account'}
						</p>
					</div>
				</div>

				{#if !profile.email_verified}
					<div class="mt-6 rounded-lg border border-amber-200 bg-amber-50 p-4">
						<p class="text-sm text-amber-800">
							We sent a verification code to <strong>{email}</strong>. Enter it below to activate
							your account.
						</p>
					</div>
					<form class="mt-5" onsubmit={verifyEmail}>
						<label for="verification-code" class="block text-sm font-medium text-gray-700">
							Verification code
						</label>
						<div class="mt-1.5 flex flex-col gap-3 sm:flex-row">
							<input
								id="verification-code"
								class="min-w-0 flex-1 rounded-lg border border-gray-300 px-3 py-2.5 text-gray-900 shadow-sm outline-none placeholder:text-gray-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-100"
								type="text"
								name="code"
								placeholder="Enter your code"
								autocomplete="one-time-code"
								bind:value={code}
								required
							/>
							<input type="hidden" bind:value={email} name="email" required />
							<button
								disabled={loading}
								class="inline-flex cursor-pointer items-center justify-center gap-2 rounded-lg bg-blue-600 px-4 py-2.5 font-medium text-white shadow-sm hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-50"
							>
								<BadgeCheck size={18} />
								{loading ? 'Verifying…' : 'Verify email'}
							</button>
						</div>
					</form>
					<button
						type="button"
						disabled={loading}
						onclick={resendVerificationEmail}
						class="mt-4 inline-flex cursor-pointer items-center gap-2 text-sm font-medium text-blue-600 hover:text-blue-800 disabled:cursor-not-allowed disabled:opacity-50"
					>
						<Send size={16} />
						Resend verification email
					</button>
				{:else if profile.identity_provider == 'default'}
					<form class="mt-6 space-y-4" onsubmit={changePassword}>
						<div>
							<label for="old-password" class="block text-sm font-medium text-gray-700">
								Current password
							</label>
							<input
								id="old-password"
								class="mt-1.5 block w-full rounded-lg border border-gray-300 px-3 py-2.5 text-gray-900 shadow-sm outline-none placeholder:text-gray-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-100"
								bind:value={changePasswordRequest.old_password}
								type="password"
								name="old_password"
								autocomplete="current-password"
								required
							/>
						</div>
						<div class="grid gap-4 sm:grid-cols-2">
							<div>
								<label for="new-password" class="block text-sm font-medium text-gray-700">
									New password
								</label>
								<input
									id="new-password"
									class="mt-1.5 block w-full rounded-lg border border-gray-300 px-3 py-2.5 text-gray-900 shadow-sm outline-none placeholder:text-gray-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-100"
									bind:value={changePasswordRequest.password}
									type="password"
									name="password"
									autocomplete="new-password"
									required
								/>
							</div>
							<div>
								<label for="confirm-password" class="block text-sm font-medium text-gray-700">
									Confirm new password
								</label>
								<input
									id="confirm-password"
									class="mt-1.5 block w-full rounded-lg border border-gray-300 px-3 py-2.5 text-gray-900 shadow-sm outline-none placeholder:text-gray-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-100"
									bind:value={changePasswordRequest.confirm_password}
									type="password"
									name="confirm_password"
									autocomplete="new-password"
									required
								/>
							</div>
						</div>
						<div class="flex justify-end pt-2">
							<button
								disabled={loading}
								class="inline-flex cursor-pointer items-center justify-center gap-2 rounded-lg bg-blue-600 px-4 py-2.5 font-medium text-white shadow-sm hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-50"
							>
								<KeyRound size={18} />
								{loading ? 'Updating…' : 'Update password'}
							</button>
						</div>
					</form>
				{:else}
					<div class="mt-6 rounded-lg border border-green-200 bg-green-50 p-4">
						<div class="flex gap-3">
							<ShieldCheck class="mt-0.5 shrink-0 text-green-600" size={20} />
							<p class="text-sm text-green-800">
								Your password is managed by <strong>{profile.identity_provider}</strong>. Use that
								service to update your sign-in credentials.
							</p>
						</div>
					</div>
				{/if}
			</section>
		</div>
	</div>
{/if}
