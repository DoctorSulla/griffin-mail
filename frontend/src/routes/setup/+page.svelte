<script lang="ts">
	import { api } from '$lib/api';

	let email = '';
	let username = '';
	let password = '';
	let confirmPassword = '';
	let loading = false;
	let error = '';
	let created = false;

	async function createAdministrator() {
		loading = true;
		error = '';

		const result = await api.createAdministrator({
			username,
			email,
			password,
			confirm_password: confirmPassword
		});

		if (result.response_type === 'Error') {
			error = result.message;
		} else {
			created = true;
		}
		loading = false;
	}
</script>

<div class="flex min-h-screen items-center justify-center bg-gray-50 px-4 py-12 sm:px-6 lg:px-8">
	<div class="w-full max-w-md space-y-8">
		<div>
			<h1 class="mt-6 text-center text-3xl font-extrabold text-gray-900">Set up Griffin Mail</h1>
			<p class="mt-2 text-center text-sm text-gray-600">
				Create the first administrator account. This account will be able to manage lists,
				recipients, and user permissions.
			</p>
		</div>

		{#if created}
			<div class="rounded-md border border-green-200 bg-green-50 p-5 text-center">
				<p class="font-medium text-green-800">Administrator account created.</p>
				<a
					href="/login"
					class="mt-4 inline-block rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700"
				>
					Sign in
				</a>
			</div>
		{:else}
			<form class="mt-8 space-y-6" on:submit|preventDefault={createAdministrator}>
				<div class="space-y-4">
					<div>
						<label for="setup-email" class="block text-sm font-medium text-gray-700">
							Email address
						</label>
						<input
							id="setup-email"
							name="email"
							type="email"
							autocomplete="email"
							required
							class="relative mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-gray-900 focus:border-indigo-500 focus:ring-indigo-500 focus:outline-none sm:text-sm"
							bind:value={email}
						/>
					</div>
					<div>
						<label for="setup-username" class="block text-sm font-medium text-gray-700">
							Username
						</label>
						<input
							id="setup-username"
							name="username"
							type="text"
							autocomplete="username"
							required
							class="relative mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-gray-900 focus:border-indigo-500 focus:ring-indigo-500 focus:outline-none sm:text-sm"
							bind:value={username}
						/>
					</div>
					<div>
						<label for="setup-password" class="block text-sm font-medium text-gray-700">
							Password
						</label>
						<input
							id="setup-password"
							name="password"
							type="password"
							autocomplete="new-password"
							minlength="8"
							required
							class="relative mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-gray-900 focus:border-indigo-500 focus:ring-indigo-500 focus:outline-none sm:text-sm"
							bind:value={password}
						/>
					</div>
					<div>
						<label for="setup-confirm-password" class="block text-sm font-medium text-gray-700">
							Confirm password
						</label>
						<input
							id="setup-confirm-password"
							name="confirmPassword"
							type="password"
							autocomplete="new-password"
							minlength="8"
							required
							class="relative mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-gray-900 focus:border-indigo-500 focus:ring-indigo-500 focus:outline-none sm:text-sm"
							bind:value={confirmPassword}
						/>
					</div>
				</div>

				{#if error}
					<div class="text-center text-sm text-red-600" role="alert">{error}</div>
				{/if}

				<button
					type="submit"
					disabled={loading}
					class="flex w-full justify-center rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700 focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 focus:outline-none disabled:cursor-not-allowed disabled:opacity-50"
				>
					{loading ? 'Creating administrator...' : 'Create administrator'}
				</button>
			</form>
		{/if}
	</div>
</div>
