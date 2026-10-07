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
	let emailPreview = $state('');
	let emailView = $state<'raw' | 'preview'>('raw');
	let previewLoading = $state(false);
	let previewError = $state('');
	let previewRequest = 0;

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
		if (!email.body.trim()) {
			selectEmailView('raw');
			error = 'A message is required.';
			return;
		}
		if (!confirm(`Send this email to all ${details?.recipients.length ?? 0} recipients?`)) return;
		const result = await api.sendEmailToList(listId, {
			subject: email.subject,
			body: email.body,
			from: email.from || undefined,
			reply_to: email.reply_to || undefined
		});
		showResult(result, 'Email sent to the list.');
		if (result.ok) {
			email = { subject: '', body: '', from: '', reply_to: '' };
			selectEmailView('raw');
		}
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

	function selectEmailView(view: 'raw' | 'preview') {
		emailView = view;
		// Invalidate requests when leaving the preview or starting a new one.
		previewRequest += 1;
		emailPreview = '';
		previewError = '';
		previewLoading = false;
		if (view === 'preview' && email.body.trim()) void showPreview(previewRequest);
	}

	async function showPreview(request: number) {
		const markdown = email.body;
		previewLoading = true;
		const result = await api.getEmailPreview({ markdown });
		if (request !== previewRequest || markdown !== email.body) return;
		previewLoading = false;
		if (result.ok && typeof result.data?.html === 'string') {
			emailPreview = result.data.html;
		} else {
			previewError = result.message || 'Could not render the preview. Please try again.';
		}
	}

	function handleTabKey(event: KeyboardEvent) {
		let view: 'raw' | 'preview';
		if (event.key === 'ArrowLeft' || event.key === 'ArrowRight') {
			view = emailView === 'raw' ? 'preview' : 'raw';
		} else if (event.key === 'Home') {
			view = 'raw';
		} else if (event.key === 'End') {
			view = 'preview';
		} else return;
		event.preventDefault();
		selectEmailView(view);
		document.getElementById(`email-${view}-tab`)?.focus();
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
					<div>
						<div
							role="tablist"
							aria-label="Message view"
							class="mb-2 flex border-b border-gray-200"
						>
							{#each ['raw', 'preview'] as view}
								<button
									type="button"
									role="tab"
									id={`email-${view}-tab`}
									aria-selected={emailView === view}
									aria-controls={`email-${view}-panel`}
									tabindex={emailView === view ? 0 : -1}
									onclick={() => selectEmailView(view === 'raw' ? 'raw' : 'preview')}
									onkeydown={handleTabKey}
									class="border-b-2 px-4 py-2 text-sm font-medium focus-visible:outline focus-visible:outline-2 focus-visible:outline-blue-600 {emailView ===
									view
										? 'border-blue-600 text-blue-700'
										: 'border-transparent text-gray-600 hover:text-gray-900'}"
								>
									{view === 'raw' ? 'Raw Markdown' : 'Preview'}
								</button>
							{/each}
						</div>
						<div
							id="email-raw-panel"
							role="tabpanel"
							aria-labelledby="email-raw-tab"
							hidden={emailView !== 'raw'}
						>
							<textarea
								required={emailView === 'raw'}
								rows="7"
								bind:value={email.body}
								aria-label="Message in Markdown"
								placeholder="Message (Markdown supported)"
								class="w-full rounded-md border border-gray-300 px-3 py-2"
							></textarea>
						</div>
						<div
							id="email-preview-panel"
							role="tabpanel"
							aria-labelledby="email-preview-tab"
							aria-busy={previewLoading}
							tabindex="0"
							hidden={emailView !== 'preview'}
							class="min-h-48 rounded-md border border-gray-300 p-3"
						>
							{#if previewLoading}
								<p role="status" class="text-sm text-gray-500">Rendering preview…</p>
							{:else if previewError}
								<p role="alert" class="text-sm text-red-700">{previewError}</p>
								<button
									type="button"
									onclick={() => selectEmailView('preview')}
									class="mt-2 text-sm font-medium text-blue-600 underline">Retry preview</button
								>
							{:else if !email.body.trim()}
								<p class="text-sm text-gray-500">
									Write a message in the Raw Markdown tab to preview it.
								</p>
							{:else}
								<div id="email-preview">{@html emailPreview}</div>
							{/if}
						</div>
					</div>
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

<style>
	/* Tailwind's reset removes Markdown defaults; keep these styles inside the preview. */
	#email-preview {
		color: #1f2937;
		line-height: 1.65;
		overflow-x: auto;
		overflow-wrap: anywhere;
	}

	#email-preview :global(h1),
	#email-preview :global(h2),
	#email-preview :global(h3),
	#email-preview :global(h4),
	#email-preview :global(h5),
	#email-preview :global(h6) {
		margin: 1.25em 0 0.5em;
		font-weight: 600;
		line-height: 1.3;
	}

	#email-preview :global(h1) {
		font-size: 24px;
	}
	#email-preview :global(h2) {
		font-size: 20px;
	}
	#email-preview :global(h3) {
		font-size: 16px;
	}
	#email-preview :global(h4) {
		font-size: 15px;
	}
	#email-preview :global(h5),
	#email-preview :global(h6) {
		font-size: 14px;
	}

	#email-preview :global(p),
	#email-preview :global(ul),
	#email-preview :global(ol),
	#email-preview :global(blockquote),
	#email-preview :global(pre),
	#email-preview :global(table) {
		margin: 0.75em 0;
	}

	#email-preview :global(ul) {
		list-style-type: disc;
		padding-left: 1.5em;
	}
	#email-preview :global(ol) {
		list-style-type: decimal;
		padding-left: 1.5em;
	}
	#email-preview :global(ul ul) {
		list-style-type: circle;
	}
	#email-preview :global(ul ul ul) {
		list-style-type: square;
	}
	#email-preview :global(li) {
		margin: 0.25em 0;
	}
	#email-preview :global(li > ul),
	#email-preview :global(li > ol) {
		margin: 0.25em 0;
	}

	#email-preview :global(a) {
		color: #2563eb;
		text-decoration: underline;
	}
	#email-preview :global(a:hover) {
		color: #1e40af;
	}
	#email-preview :global(strong) {
		font-weight: 700;
	}
	#email-preview :global(em) {
		font-style: italic;
	}
	#email-preview :global(del) {
		text-decoration: line-through;
	}

	#email-preview :global(blockquote) {
		border-left: 4px solid #d1d5db;
		padding: 0.25em 1em;
		color: #4b5563;
		background: #f9fafb;
	}

	#email-preview :global(code) {
		border-radius: 0.25rem;
		padding: 0.15em 0.35em;
		background: #f3f4f6;
		font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
		font-size: 0.875em;
	}

	#email-preview :global(pre) {
		overflow-x: auto;
		border-radius: 0.375rem;
		padding: 1em;
		background: #f3f4f6;
		line-height: 1.5;
	}

	#email-preview :global(pre code) {
		padding: 0;
		background: transparent;
	}
	#email-preview :global(hr) {
		margin: 1.5em 0;
		border-top: 1px solid #d1d5db;
	}
	#email-preview :global(img) {
		max-width: 100%;
		height: auto;
		margin: 0.75em 0;
	}
	#email-preview :global(table) {
		border-collapse: collapse;
		font-size: 0.875em;
	}
	#email-preview :global(th),
	#email-preview :global(td) {
		border: 1px solid #d1d5db;
		padding: 0.5em 0.75em;
	}
	#email-preview :global(th) {
		background: #f3f4f6;
		font-weight: 600;
	}
	#email-preview :global(tbody tr:nth-child(even)) {
		background: #f9fafb;
	}
	#email-preview :global(> :first-child) {
		margin-top: 0;
	}
	#email-preview :global(> :last-child) {
		margin-bottom: 0;
	}
</style>
