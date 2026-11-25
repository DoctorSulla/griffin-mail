<script lang="ts">
	import { onMount } from 'svelte';
	import CircleX from '@lucide/svelte/icons/circle-x';
	import CirclePlus from '@lucide/svelte/icons/circle-plus';
	import { api, type Recipient } from '$lib/api';
	import Feedback from '$lib/Feedback.svelte';

	let newRecipients: Recipient[] = $state([{ name: '', email: '' }]);
	let recipients: Required<Recipient>[] = $state([]);
	let recipientFilter = $state('');
	let loading = $state(false);
	let error = $state('');
	let success = $state('');

	let filteredRecipients = $derived.by(() => {
		const query = recipientFilter.trim().toLowerCase();
		if (!query) return recipients;
		return recipients.filter(
			(recipient) =>
				recipient.name.toLowerCase().includes(query) ||
				recipient.email.toLowerCase().includes(query)
		);
	});

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
				<p class="text-sm text-gray-500">
					{#if recipientFilter.trim()}
						Showing {filteredRecipients.length} of {recipients.length} in directory
					{:else}
						{recipients.length} in directory
					{/if}
				</p>
				<input
					type="search"
					bind:value={recipientFilter}
					placeholder="Filter existing recipients by name or email…"
					aria-label="Filter existing recipients"
					class="mt-3 w-full rounded-md border border-gray-300 px-3 py-2 text-sm"
				/>
				<div class="mt-3 max-h-96 divide-y divide-gray-100 overflow-y-auto pr-4">
					{#each filteredRecipients as recipient (recipient.id)}
						<div class="flex items-center justify-between gap-4 py-3">
							<div class="min-w-0">
								<p class="truncate font-medium text-gray-900">{recipient.name}</p>
								<p class="truncate text-sm text-gray-600">{recipient.email}</p>
							</div>
							<button
								type="button"
								onclick={() => deleteRecipient(recipient)}
								class="shrink-0 text-sm font-medium text-red-600 hover:text-red-800">Delete</button
							>
						</div>
					{:else}
						<p class="py-4 text-sm text-gray-500">No matching recipients.</p>
					{/each}
				</div>
			{/if}
		</section>
	</div>
</div>
