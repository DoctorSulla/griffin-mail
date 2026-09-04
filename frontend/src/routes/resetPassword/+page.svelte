<script lang="ts">
	import { goto } from '$app/navigation';
	import { api } from '$lib/api';
	import Feedback from '$lib/Feedback.svelte';

	let email = $state('');
	let code = $state('');
	let password = $state('');
	let confirmPassword = $state('');
	let codeRequested = $state(false);
	let loading = $state(false);
	let error = $state('');
	let success = $state('');

	async function requestCode(event: SubmitEvent) {
		event.preventDefault();
		loading = true;
		error = '';
		const result = await api.resetPassword(email);
		loading = false;
		if (result.response_type === 'Error') {
			error = result.message;
		} else {
			codeRequested = true;
			success = result.message;
		}
	}

	async function completeReset(event: SubmitEvent) {
		event.preventDefault();
		loading = true;
		error = '';
		const result = await api.completeResetPassword({
			code,
			password,
			confirm_password: confirmPassword
		});
		loading = false;
		if (result.response_type === 'Error') {
			error = result.message;
		} else {
			goto('/login');
		}
	}
</script>

<div class="mx-auto max-w-lg py-10">
	<h1 class="text-3xl font-bold text-gray-900">Reset your password</h1>
	<p class="mt-1 text-gray-600">Request a reset code, then enter it with your new password.</p>

	<div class="mt-6 space-y-4">
		<Feedback {error} {success} />
		{#if !codeRequested}
			<form
				class="space-y-4 rounded-lg border border-gray-200 bg-white p-6 shadow-sm"
				onsubmit={requestCode}
			>
				<div>
					<label for="reset-email" class="block text-sm font-medium text-gray-700">Email</label>
					<input
						id="reset-email"
						type="email"
						required
						bind:value={email}
						class="mt-1 w-full rounded-md border border-gray-300 px-3 py-2"
					/>
				</div>
				<button
					disabled={loading}
					class="rounded-md bg-blue-600 px-4 py-2 font-medium text-white hover:bg-blue-700 disabled:opacity-50"
					>{loading ? 'Sending…' : 'Send reset code'}</button
				>
			</form>
		{:else}
			<form
				class="space-y-4 rounded-lg border border-gray-200 bg-white p-6 shadow-sm"
				onsubmit={completeReset}
			>
				<div>
					<label for="reset-code" class="block text-sm font-medium text-gray-700">Reset code</label>
					<input
						id="reset-code"
						required
						bind:value={code}
						class="mt-1 w-full rounded-md border border-gray-300 px-3 py-2"
					/>
				</div>
				<div>
					<label for="new-password" class="block text-sm font-medium text-gray-700"
						>New password</label
					>
					<input
						id="new-password"
						type="password"
						minlength="8"
						required
						bind:value={password}
						class="mt-1 w-full rounded-md border border-gray-300 px-3 py-2"
					/>
				</div>
				<div>
					<label for="confirm-password" class="block text-sm font-medium text-gray-700">
						Confirm new password
					</label>
					<input
						id="confirm-password"
						type="password"
						minlength="8"
						required
						bind:value={confirmPassword}
						class="mt-1 w-full rounded-md border border-gray-300 px-3 py-2"
					/>
				</div>
				<div class="flex gap-3">
					<button
						disabled={loading}
						class="rounded-md bg-blue-600 px-4 py-2 font-medium text-white hover:bg-blue-700 disabled:opacity-50"
						>{loading ? 'Resetting…' : 'Reset password'}</button
					>
					<button
						type="button"
						onclick={() => {
							codeRequested = false;
							success = '';
						}}
						class="rounded-md border border-gray-300 px-4 py-2 text-gray-700"
						>Request another code</button
					>
				</div>
			</form>
		{/if}
	</div>
</div>
