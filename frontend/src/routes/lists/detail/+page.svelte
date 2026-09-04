<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import {
		api,
		type ListWithRecipients,
		type Recipient,
		type UserPermission,
		type ListPermission
	} from '$lib/api';
	import Feedback from '$lib/Feedback.svelte';

	let listId = $state(0);
	let details: ListWithRecipients | null = $state(null);
	let available: Required<Recipient>[] = $state([]);
	let permissions: UserPermission[] = $state([]);
	let loading = $state(true);
	let error = $state('');
	let success = $state('');
	let availableMessage = $state('');
	let permissionMessage = $state('');

	let email = $state({ subject: '', body: '', from: '', reply_to: '' });
	let permissionEmail = $state('');
	let permission: ListPermission = $state('read');

	async function loadList() {
		if (!Number.isInteger(listId) || listId < 1) {
			error = 'A valid list ID is required.';
			loading = false;
			return;
		}
		const result = await api.getList(listId);
		if (result.ok && result.data) details = result.data;
		else error = result.message;
		loading = false;
	}

	async function loadAvailable() {
		const result = await api.getAvailableRecipients(listId);
		if (result.ok) {
			available = result.data ?? [];
			availableMessage = '';
		} else {
			availableMessage = result.message;
		}
	}

	async function loadPermissions() {
		const result = await api.getListPermissions(listId);
		if (result.ok) {
			permissions = result.data ?? [];
			permissionMessage = '';
		} else {
			permissionMessage = result.message;
		}
	}

	onMount(async () => {
		listId = Number(page.url.searchParams.get('id'));
		await loadList();
		if (details) {
			await Promise.all([loadAvailable(), loadPermissions()]);
		}
	});

	function showResult(result: { ok: boolean; message: string }, successMessage: string) {
		if (result.ok) {
			success = successMessage;
			error = '';
		} else {
			error = result.message;
			success = '';
		}
	}

	async function addRecipient(recipient: Required<Recipient>) {
		const result = await api.addRecipientsToList(listId, [recipient.id]);
		showResult(result, `${recipient.name} added to the list.`);
		if (result.ok) await Promise.all([loadList(), loadAvailable()]);
	}

	async function removeRecipient(recipient: Required<Recipient>) {
		const result = await api.removeRecipientsFromList(listId, [recipient.id]);
		showResult(result, `${recipient.name} removed from the list.`);
		if (result.ok) await Promise.all([loadList(), loadAvailable()]);
	}

	async function sendEmail(event: SubmitEvent) {
		event.preventDefault();
		if (!confirm(`Send this email to all ${details?.recipients.length ?? 0} recipients?`)) return;
		const result = await api.sendEmailToList(listId, {
			subject: email.subject,
			body: email.body,
			from: email.from || undefined,
			reply_to: email.reply_to || undefined
		});
		showResult(result, 'Email sent to the list.');
		if (result.ok) email = { subject: '', body: '', from: '', reply_to: '' };
	}

	async function grantPermission(event: SubmitEvent) {
		event.preventDefault();
		const result = await api.addListPermissions(listId, [
			{ user_email: permissionEmail, permission }
		]);
		showResult(result, 'Permission granted.');
		if (result.ok) {
			permissionEmail = '';
			await loadPermissions();
		}
	}

	async function revokePermission(item: UserPermission) {
		const result = await api.deleteListPermissions(listId, [item]);
		showResult(result, 'Permission revoked.');
		if (result.ok) await loadPermissions();
	}

	async function deleteList() {
		if (!details || !confirm(`Permanently delete "${details.list.name}"?`)) return;
		const result = await api.deleteList(listId);
		if (result.ok) goto('/lists');
		else showResult(result, '');
	}
</script>

<div class="py-8">
	<a class="text-sm font-medium text-blue-600 hover:text-blue-800" href="/lists">← All lists</a>

	{#if loading}
		<p class="mt-6 text-gray-500">Loading list…</p>
	{:else if details}
		<div class="mt-3 flex flex-wrap items-start justify-between gap-4">
			<div>
				<h1 class="text-3xl font-bold text-gray-900">{details.list.name}</h1>
				<p class="mt-1 text-gray-600">{details.list.description}</p>
			</div>
			<button
				type="button"
				onclick={deleteList}
				class="rounded-md border border-red-300 px-4 py-2 text-sm font-medium text-red-700 hover:bg-red-50"
				>Delete list</button
			>
		</div>

		<div class="mt-5 space-y-3">
			<Feedback {error} {success} />
		</div>

		<div class="mt-6 grid gap-6 lg:grid-cols-2">
			<section class="rounded-lg border border-gray-200 bg-white p-5 shadow-sm">
				<h2 class="text-xl font-semibold text-gray-900">Current recipients</h2>
				<p class="text-sm text-gray-500">{details.recipients.length} on this list</p>
				<div class="mt-3 divide-y divide-gray-100">
					{#each details.recipients as recipient}
						<div class="flex items-center justify-between gap-3 py-3">
							<div>
								<p class="font-medium">{recipient.name}</p>
								<p class="text-sm text-gray-600">{recipient.email}</p>
							</div>
							<button
								type="button"
								onclick={() => removeRecipient(recipient)}
								class="text-sm font-medium text-red-600 hover:text-red-800">Remove</button
							>
						</div>
					{:else}
						<p class="py-4 text-sm text-gray-500">This list is empty.</p>
					{/each}
				</div>
			</section>

			<section class="rounded-lg border border-gray-200 bg-white p-5 shadow-sm">
				<h2 class="text-xl font-semibold text-gray-900">Add recipients</h2>
				{#if availableMessage}
					<p class="mt-3 text-sm text-amber-700">{availableMessage}</p>
				{:else}
					<div class="mt-3 max-h-80 divide-y divide-gray-100 overflow-auto">
						{#each available as recipient}
							<div class="flex items-center justify-between gap-3 py-3">
								<div>
									<p class="font-medium">{recipient.name}</p>
									<p class="text-sm text-gray-600">{recipient.email}</p>
								</div>
								<button
									type="button"
									onclick={() => addRecipient(recipient)}
									class="text-sm font-medium text-blue-600 hover:text-blue-800">Add</button
								>
							</div>
						{:else}
							<p class="py-4 text-sm text-gray-500">
								Every directory recipient is already on this list.
							</p>
						{/each}
					</div>
				{/if}
			</section>

			<form class="rounded-lg border border-gray-200 bg-white p-5 shadow-sm" onsubmit={sendEmail}>
				<h2 class="text-xl font-semibold text-gray-900">Send an email</h2>
				<div class="mt-4 space-y-3">
					<input
						required
						bind:value={email.subject}
						placeholder="Subject"
						class="w-full rounded-md border border-gray-300 px-3 py-2"
					/>
					<textarea
						required
						rows="7"
						bind:value={email.body}
						placeholder="Message"
						class="w-full rounded-md border border-gray-300 px-3 py-2"
					></textarea>
					<div class="grid gap-3 sm:grid-cols-2">
						<input
							type="email"
							bind:value={email.from}
							placeholder="From (SMTP default)"
							class="w-full rounded-md border border-gray-300 px-3 py-2"
						/>
						<input
							type="email"
							bind:value={email.reply_to}
							placeholder="Reply-to (optional)"
							class="w-full rounded-md border border-gray-300 px-3 py-2"
						/>
					</div>
					<button class="rounded-md bg-blue-600 px-4 py-2 font-medium text-white hover:bg-blue-700">
						Send to {details.recipients.length} recipients
					</button>
				</div>
			</form>

			<section class="rounded-lg border border-gray-200 bg-white p-5 shadow-sm">
				<h2 class="text-xl font-semibold text-gray-900">List permissions</h2>
				<form class="mt-4 flex flex-wrap gap-2" onsubmit={grantPermission}>
					<input
						type="email"
						required
						bind:value={permissionEmail}
						placeholder="User email"
						class="min-w-56 flex-1 rounded-md border border-gray-300 px-3 py-2"
					/>
					<select bind:value={permission} class="rounded-md border border-gray-300 px-3 py-2">
						<option value="read">Read</option>
						<option value="write">Write</option>
						<option value="send">Send</option>
						<option value="change_permission">Manage permissions</option>
					</select>
					<button class="rounded-md bg-blue-600 px-4 py-2 font-medium text-white hover:bg-blue-700">
						Grant
					</button>
				</form>
				{#if permissionMessage}
					<p class="mt-3 text-sm text-amber-700">{permissionMessage}</p>
				{:else}
					<div class="mt-4 max-h-64 divide-y divide-gray-100 overflow-auto">
						{#each permissions as item}
							<div class="flex items-center justify-between gap-3 py-2 text-sm">
								<span><strong>{item.user_email}</strong> · {item.permission.replace('_', ' ')}</span
								>
								<button
									type="button"
									onclick={() => revokePermission(item)}
									class="font-medium text-red-600 hover:text-red-800">Revoke</button
								>
							</div>
						{/each}
					</div>
				{/if}
			</section>
		</div>
	{:else}
		<div class="mt-6"><Feedback {error} /></div>
	{/if}
</div>
