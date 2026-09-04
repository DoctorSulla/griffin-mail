<script lang="ts">
	import { onMount } from 'svelte';
	import CircleX from '@lucide/svelte/icons/circle-x';
	import CirclePlus from '@lucide/svelte/icons/circle-plus';
	import { api, type Recipient } from '$lib/api';
	import Feedback from '$lib/Feedback.svelte';

	let newRecipients: Recipient[] = $state([{ name: '', email: '' }]);
	let recipients: Required<Recipient>[] = $state([]);
	let loading = $state(false);
	let error = $state('');
	let success = $state('');

	async function loadRecipients() {
		const result = await api.getRecipients();
		if (result.ok) {
			recipients = result.data ?? [];
		} else {
			error = result.message;
		}
	}

	onMount(loadRecipients);

	async function submitRecipients(event: SubmitEvent) {
		event.preventDefault();
		loading = true;
		error = '';
		success = '';
		const result = await api.addRecipients(newRecipients);
		loading = false;
		if (result.response_type === 'Error') {
			error = result.message;
		} else {
			success = 'Recipients added.';
			newRecipients = [{ name: '', email: '' }];
			await loadRecipients();
		}
	}

	async function deleteRecipient(recipient: Required<Recipient>) {
		if (!confirm(`Delete ${recipient.email} from the recipient directory and every list?`)) return;
		const result = await api.deleteRecipient(recipient.email);
		if (result.ok) {
			success = 'Recipient deleted.';
			error = '';
			await loadRecipients();
		} else {
			error = result.message;
			success = '';
		}
	}
</script>

<div class="py-8">
	<h1 class="text-3xl font-bold text-gray-900">Recipient directory</h1>
	<p class="mt-1 text-gray-600">Create recipients before adding them to mailing lists.</p>

	<div class="mt-6 grid gap-6 lg:grid-cols-[2fr_3fr]">
		<form
			class="space-y-4 rounded-lg border border-gray-200 bg-white p-5 shadow-sm"
			onsubmit={submitRecipients}
		>
			<h2 class="text-lg font-semibold text-gray-900">Add recipients</h2>
			{#each newRecipients as recipient, index}
				<div class="grid grid-cols-[1fr_1fr_auto] gap-2">
					<input
						class="rounded-md border border-gray-300 px-3 py-2"
						placeholder="Name"
						bind:value={recipient.name}
						required
					/>
					<input
						class="rounded-md border border-gray-300 px-3 py-2"
						placeholder="Email"
						bind:value={recipient.email}
						type="email"
						required
					/>
					<button
						type="button"
						aria-label="Remove row"
						disabled={newRecipients.length === 1}
						onclick={() => newRecipients.splice(index, 1)}
						class="text-red-600 disabled:invisible"><CircleX /></button
					>
				</div>
			{/each}
			<button
				type="button"
				onclick={() => newRecipients.push({ name: '', email: '' })}
				class="flex items-center gap-2 text-sm font-medium text-green-700"
				><CirclePlus size={18} /> Add another</button
			>
			<button
				type="submit"
				disabled={loading}
				class="rounded-md bg-blue-600 px-4 py-2 font-medium text-white hover:bg-blue-700 disabled:opacity-50"
				>{loading ? 'Adding…' : 'Add recipients'}</button
			>
			<Feedback {error} {success} />
		</form>

		<section class="rounded-lg border border-gray-200 bg-white p-5 shadow-sm">
			<h2 class="text-lg font-semibold text-gray-900">Existing recipients</h2>
			{#if recipients.length === 0}
				<p class="mt-4 text-sm text-gray-500">
					No recipients found, or you do not have directory permission.
				</p>
			{:else}
				<div class="mt-4 divide-y divide-gray-100">
					{#each recipients as recipient}
						<div class="flex items-center justify-between gap-4 py-3">
							<div>
								<p class="font-medium text-gray-900">{recipient.name}</p>
								<p class="text-sm text-gray-600">{recipient.email}</p>
							</div>
							<button
								type="button"
								onclick={() => deleteRecipient(recipient)}
								class="text-sm font-medium text-red-600 hover:text-red-800">Delete</button
							>
						</div>
					{/each}
				</div>
			{/if}
		</section>
	</div>
</div>
