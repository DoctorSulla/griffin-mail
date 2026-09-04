<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type MailingList } from '$lib/api';
	import Feedback from '$lib/Feedback.svelte';

	let lists: MailingList[] = $state([]);
	let loading = $state(true);
	let error = $state('');

	onMount(async () => {
		const result = await api.getLists();
		if (result.ok) {
			lists = result.data ?? [];
		} else {
			error = result.message;
		}
		loading = false;
	});
</script>

<div class="py-8">
	<div class="mb-6 flex items-center justify-between gap-4">
		<div>
			<h1 class="text-3xl font-bold text-gray-900">Mailing lists</h1>
			<p class="mt-1 text-gray-600">View the lists you can access and manage their recipients.</p>
		</div>
		<a
			class="rounded-md bg-blue-600 px-4 py-2 font-medium text-white hover:bg-blue-700"
			href="/createList"
		>
			Create list
		</a>
	</div>

	<Feedback {error} />

	{#if loading}
		<p class="mt-6 text-gray-500">Loading lists…</p>
	{:else if lists.length === 0 && !error}
		<div class="mt-6 rounded-lg border border-dashed border-gray-300 p-10 text-center">
			<h2 class="font-semibold text-gray-900">No lists available</h2>
			<p class="mt-1 text-sm text-gray-600">Create a list or ask for read permission to one.</p>
		</div>
	{:else}
		<div class="mt-6 grid gap-4 md:grid-cols-2 lg:grid-cols-3">
			{#each lists as list}
				<a
					href={`/lists/detail?id=${list.id}`}
					class="rounded-lg border border-gray-200 bg-white p-5 shadow-sm transition hover:border-blue-300 hover:shadow"
				>
					<h2 class="text-xl font-semibold text-gray-900">{list.name}</h2>
					<p class="mt-2 text-sm text-gray-600">{list.description}</p>
					<p class="mt-4 text-sm font-medium text-blue-600">Open list →</p>
				</a>
			{/each}
		</div>
	{/if}
</div>
