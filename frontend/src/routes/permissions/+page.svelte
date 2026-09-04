<script lang="ts">
	import { api, type GlobalPermission } from '$lib/api';
	import Feedback from '$lib/Feedback.svelte';

	let userEmail = $state('');
	let permission: GlobalPermission = $state('manage_list');
	let loading = $state(false);
	let error = $state('');
	let success = $state('');

	async function changePermission(action: 'grant' | 'revoke') {
		loading = true;
		error = '';
		success = '';
		const payload = [{ user_email: userEmail, permission }];
		const result =
			action === 'grant'
				? await api.addGlobalPermissions(payload)
				: await api.deleteGlobalPermissions(payload);
		loading = false;

		if (result.ok) {
			success = `Permission ${action === 'grant' ? 'granted' : 'revoked'}.`;
			userEmail = '';
		} else {
			error = result.message;
		}
	}

	function submit(event: SubmitEvent, action: 'grant' | 'revoke') {
		event.preventDefault();
		changePermission(action);
	}
</script>

<div class="mx-auto max-w-2xl py-8">
	<h1 class="text-3xl font-bold text-gray-900">Global permissions</h1>
	<p class="mt-1 text-gray-600">
		Grant or revoke application-wide management rights. You need the global change-permission right.
	</p>

	<form
		class="mt-6 space-y-5 rounded-lg border border-gray-200 bg-white p-6 shadow-sm"
		onsubmit={(event) => submit(event, 'grant')}
	>
		<div>
			<label for="permission-email" class="block text-sm font-medium text-gray-700"
				>User email</label
			>
			<input
				id="permission-email"
				type="email"
				required
				bind:value={userEmail}
				class="mt-1 w-full rounded-md border border-gray-300 px-3 py-2"
			/>
		</div>
		<div>
			<label for="global-permission" class="block text-sm font-medium text-gray-700"
				>Permission</label
			>
			<select
				id="global-permission"
				bind:value={permission}
				class="mt-1 w-full rounded-md border border-gray-300 px-3 py-2"
			>
				<option value="manage_list">Create and delete lists</option>
				<option value="manage_recipient">Create and delete recipients</option>
				<option value="change_permission">Manage global permissions</option>
			</select>
		</div>
		<Feedback {error} {success} />
		<div class="flex gap-3">
			<button
				type="submit"
				disabled={loading}
				class="rounded-md bg-blue-600 px-4 py-2 font-medium text-white hover:bg-blue-700 disabled:opacity-50"
				>Grant</button
			>
			<button
				type="button"
				disabled={loading || !userEmail}
				onclick={() => changePermission('revoke')}
				class="rounded-md border border-red-300 px-4 py-2 font-medium text-red-700 hover:bg-red-50 disabled:opacity-50"
				>Revoke</button
			>
		</div>
	</form>
</div>
