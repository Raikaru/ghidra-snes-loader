// SPDX-License-Identifier: MIT
// Originally by achan1989; expanded for headless / current Ghidra usage.
package snesloader;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.app.util.opinion.QueryOpinionService;
import ghidra.app.util.opinion.QueryResult;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import snesloader.RomInfo.RomKind;

/**
 * Top-level Ghidra loader for Super Nintendo / Super Famicom ROMs.
 *
 * <p>Handles ROM kind detection (LoROM/HiROM, with or without an SMC copier
 * header), maps ROM banks into the 65816 24-bit bus space, and (optionally)
 * lays down WRAM, hardware-register, SRAM and interrupt-vector annotations
 * so that the program is immediately useful for analysis.</p>
 */
public class SnesLoader extends AbstractLibrarySupportLoader {

	public static final String LOADER_NAME = "SNES ROM";

	public static final String OPT_HW_REGS = "Map SNES hardware registers";
	public static final String OPT_VECTORS = "Mark interrupt vectors";
	public static final String OPT_HEADER_DT = "Apply Cartridge Header datatype";
	public static final String OPT_LOWRAM_MIRROR = "Map LowRAM mirror at $00:0000";
	public static final String OPT_SRAM = "Map cartridge SRAM (when present)";

	@Override
	public String getName() {
		return LOADER_NAME;
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 50;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		if (detectRomKinds(provider).isEmpty()) {
			return loadSpecs;
		}
		// QueryOpinionService is the canonical way to look up languages declared in
		// `<processor>.opinion` files. It does the right thing without forcing the
		// 65816 processor to be registered ahead of time (Processor.toProcessor
		// throws a ProcessorNotFoundException for lazily-registered processors when
		// it's the first loader to run).
		List<QueryResult> results = QueryOpinionService.query(LOADER_NAME, null, null);
		if (results == null || results.isEmpty()) {
			return loadSpecs;
		}
		for (QueryResult r : results) {
			loadSpecs.add(new LoadSpec(this, 0, r));
		}
		return loadSpecs;
	}

	private static Collection<RomInfo> detectRomKinds(ByteProvider provider) {
		Collection<RomInfo> valid = new HashSet<>();
		for (RomKind kind : RomKind.values()) {
			for (boolean smc : new boolean[] { false, true }) {
				RomInfo r = new RomInfo(kind, smc);
				if (r.bytesLookValid(provider)) {
					valid.add(r);
				}
			}
		}
		return valid;
	}

	@Override
	protected void load(Program program, ImporterSettings settings) throws IOException {
		ByteProvider provider = settings.provider();
		MessageLog log = settings.log();

		Collection<RomInfo> detected = detectRomKinds(provider);
		if (detected.isEmpty()) {
			throw new IOException("Not a valid SNES ROM (file changed since import?)");
		}
		RomInfo romInfo = pickBestMatch(detected);
		if (romInfo == null) {
			StringBuilder sb = new StringBuilder("Cannot uniquely identify SNES ROM. Candidates:\n");
			for (RomInfo r : detected) {
				sb.append("  ").append(r.getDescription()).append('\n');
			}
			Msg.showError(this, null, "SNES Loader", sb.toString());
			throw new IOException(sb.toString());
		}

		// Re-parse with the chosen kind so the header is cached on the RomInfo.
		romInfo.bytesLookValid(provider);

		log.appendMsg(LOADER_NAME, "Loading " + romInfo.getDescription());
		if (romInfo.getHeader() != null) {
			log.appendMsg(LOADER_NAME, romInfo.getHeader().describe());
		}

		FlatProgramAPI fpa = new FlatProgramAPI(program, settings.monitor());

		// 1) Map ROM into the 65816 bus.
		boolean ok = romInfo.getLoader().load(provider, settings.loadSpec(), settings.options(),
				log, program, settings.monitor(), romInfo);
		if (!ok) {
			throw new IOException("ROM mapping failed");
		}

		// 2) Apply WRAM / hardware regs / SRAM / vectors / header DT, per options.
		SnesPostLoader.Options opts = parseOptions(settings.options());
		try {
			SnesPostLoader.apply(fpa, romInfo, opts, log);
		}
		catch (Exception e) {
			log.appendException(e);
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram, mirrorFsLayout);

		list.add(new Option(OPT_HW_REGS, true, Boolean.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-snesHwRegs"));
		list.add(new Option(OPT_VECTORS, true, Boolean.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-snesVectors"));
		list.add(new Option(OPT_HEADER_DT, true, Boolean.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-snesHeader"));
		list.add(new Option(OPT_LOWRAM_MIRROR, true, Boolean.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-snesLowRamMirror"));
		list.add(new Option(OPT_SRAM, true, Boolean.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-snesSram"));
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		String err = super.validateOptions(provider, loadSpec, options, program);
		if (err != null || options == null) {
			return err;
		}
		for (Option opt : options) {
			String n = opt.getName();
			if (OPT_HW_REGS.equals(n) || OPT_VECTORS.equals(n) || OPT_HEADER_DT.equals(n)
					|| OPT_LOWRAM_MIRROR.equals(n) || OPT_SRAM.equals(n)) {
				if (!Boolean.class.isAssignableFrom(opt.getValueClass())) {
					return "Invalid type for option: " + n + " - " + opt.getValueClass();
				}
			}
		}
		return null;
	}

	private static RomInfo pickBestMatch(Collection<RomInfo> candidates) {
		if (candidates.size() == 1) {
			return candidates.iterator().next();
		}
		// Prefer no-SMC over SMC, and LoROM over HiROM as a tiebreaker.
		RomInfo best = null;
		int bestRank = Integer.MIN_VALUE;
		for (RomInfo r : candidates) {
			int rank = (r.hasSmcHeader() ? 0 : 10) + (r.getKind() == RomKind.HI_ROM ? 0 : 1);
			if (rank > bestRank) {
				bestRank = rank;
				best = r;
			}
		}
		return best;
	}

	private static SnesPostLoader.Options parseOptions(List<Option> options) {
		SnesPostLoader.Options o = new SnesPostLoader.Options();
		if (options == null) {
			return o;
		}
		for (Option opt : options) {
			Object v = opt.getValue();
			if (!(v instanceof Boolean)) {
				continue;
			}
			boolean b = (Boolean) v;
			switch (opt.getName()) {
				case OPT_HW_REGS:
					o.mapHwRegs = b;
					break;
				case OPT_VECTORS:
					o.markVectors = b;
					break;
				case OPT_HEADER_DT:
					o.applyHeaderDataType = b;
					break;
				case OPT_LOWRAM_MIRROR:
					o.mapLowRamMirror = b;
					break;
				case OPT_SRAM:
					o.mapSram = b;
					break;
				default:
					break;
			}
		}
		return o;
	}
}
